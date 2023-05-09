#include "Enclave_t.h"
#include "sgx_trts.h"
#include "sgx_tseal.h"

#include <stdlib.h>
#include <stdio.h>
#include <sqlite3.h>
#include <string>

sqlite3 *db;

uint8_t *current_stored_value;

int generate_matrix_card_values(uint8_t *array, size_t array_size) {
    sgx_status_t status;
    for (int i = 0; i < array_size; i++) {
        uint8_t value;
        status = sgx_read_rand(&value, sizeof(value));
        if (status != SGX_SUCCESS) {
            ocall_print_error("Error generating random number");
            return SGX_ERROR_UNEXPECTED;
        }

        array[i] = value;
    }

    return SGX_SUCCESS;
}

static int callback(void *NotUsed, int argc, char **argv, char **azColName) {
    for (int i = 0; i < argc; i++) {
        std::string azColName_str = azColName[i];
        std::string argv_str = (argv[i] ? argv[i] : "NULL");
        ocall_print_string((azColName_str + " = " + argv_str + "\n").c_str());
    }
    ocall_print_string("\n");
    return 0;
}

void ecall_get_current_stored_value(uint8_t *result) {
    result = current_stored_value;
}

static int store_text_callback(void *NotUsed, int argc, char **argv, char **azColName) {
    for (int i = 0; i < argc; i++) {
        std::string argv_str = (argv[i] ? argv[i] : "NULL");

        char *char_data = argv_str.data();
        current_stored_value = new uint8_t[strlen(char_data)];
        current_stored_value = reinterpret_cast<uint8_t *>(const_cast<char *>(char_data));
    }
    return 0;
}

void ecall_opendb(const char *dbname) {
    int rc = sqlite3_open(dbname, &db); 
    if (rc) {
        ocall_println_string("SQLite error - can't open database connection: ");
        ocall_println_string(sqlite3_errmsg(db));
        return;
    }
    ocall_print_string("Enclave: Created database connection to ");
    ocall_println_string(dbname);
}

void ecall_execute_sql(const char *sql) {
    char *zErrMsg = 0;
    int rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
    if (rc) {
        ocall_print_string("SQLite error: ");
        ocall_println_string(sqlite3_errmsg(db));
        return;
    }
}

void ecall_insert_matrix_card(uint8_t *data, uint32_t data_size) {
    const char *insert_stmt = "INSERT INTO card (matrix_data) VALUES (?);";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, insert_stmt, -1, &stmt, 0);

    rc = sqlite3_bind_blob(stmt, 1, data, data_size, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

void ecall_get_text_size(const char *sql, int *size) {
    sqlite3_stmt *stmt;

    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);

    int sz = 0;
    if ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        sz = sqlite3_column_bytes(stmt, 0);
        const void *blob_data = sqlite3_column_blob(stmt, 0);

        if (blob_data) {
            *size = -1;
        }
    }

    *size = sz;
}

void ecall_get_text_value(const char *sql, uint8_t *data_from_db, uint32_t data_from_db_size) {
    sqlite3_stmt *stmt;

    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);

    int sz;
    if ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        sz = sqlite3_column_bytes(stmt, 0);
        const void *blob_data = sqlite3_column_blob(stmt, 0);

        if (blob_data) {
            memcpy(data_from_db, blob_data, sz);
        }
    }
}

void ecall_close_db() {
    sqlite3_close(db);
    ocall_println_string("Enclave: Closed database connection");
}

uint32_t get_sealed_data_size(uint32_t fsize) {
    uint32_t size = sgx_calc_sealed_data_size(0, fsize);
    return size;
}

sgx_status_t seal_data(uint8_t* plaintext, size_t plaintext_size, uint8_t* sealed_data, size_t sealed_size) {
    sgx_status_t ret = SGX_SUCCESS;

    if (plaintext == NULL || sealed_data == NULL) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    uint32_t sealed_data_size_needed = sgx_calc_sealed_data_size(0, plaintext_size);

    if (sealed_size < sealed_data_size_needed) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    ret = sgx_seal_data(0, nullptr, plaintext_size, plaintext, sealed_data_size_needed, (sgx_sealed_data_t*)sealed_data);

    if (ret != SGX_SUCCESS) {
        return ret;
    }

    return SGX_SUCCESS;
}

sgx_status_t unseal_data(uint8_t* sealed_data, size_t sealed_size, uint8_t* plaintext, size_t plaintext_size) {
    sgx_status_t ret = SGX_SUCCESS;

    if (sealed_data == NULL || plaintext == NULL) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    uint32_t plaintext_size_needed = sgx_get_encrypt_txt_len((sgx_sealed_data_t*)sealed_data);

    if (plaintext_size < plaintext_size_needed) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    ret = sgx_unseal_data((sgx_sealed_data_t*)sealed_data, nullptr, 0, plaintext, &plaintext_size_needed);

    if (ret != SGX_SUCCESS) {
        return ret;
    }

    return SGX_SUCCESS;
}


void bootstrap_persistence() {
    ecall_opendb("matrix_cards.db");
    const char *card_table_create_query = 
        "CREATE TABLE IF NOT EXISTS card (\
            id INTEGER PRIMARY KEY AUTOINCREMENT, \
            matrix_data BLOB NOT NULL \
        );";

    ecall_execute_sql(card_table_create_query);
}


sgx_status_t ecall_validate_coords(uint32_t client_id, Coords *coords, uint8_t num_coords, uint8_t *result) {
    const char *query = "SELECT matrix_data FROM card ORDER BY id DESC LIMIT 1;";
    int size = 0;

    sgx_status_t retval = SGX_SUCCESS;

    bootstrap_persistence();

    ecall_get_text_size(query, &size);
    //printf("[-] enclave::ecall_get_text_size() = %d\n", size);

    uint8_t *sealed_from_db = new uint8_t[size];
    ecall_get_text_value(query, sealed_from_db, size);

    ocall_println_string("\n[-] enclave::seal_from_db");
    //pretty_print_arr(sealed_from_db, size - 500, 50);

    ocall_println_string("[-] enclave::unsealing");

    uint8_t *unsealed = new uint8_t[64];
    uint32_t unsealed_sz = 64;

    //ret = unseal_data(global_eid, &retval, sealed_data_buf, sealed_data_size, unsealed, unsealed_sz);
    int ret = unseal_data(sealed_from_db, size, unsealed, unsealed_sz);

    if (ret != SGX_SUCCESS) {
        ocall_println_string("error");
        free(sealed_from_db);
        return SGX_SUCCESS;
    }
    else if (retval != SGX_SUCCESS) {
        ocall_println_string("error 2");
        free(sealed_from_db);
        return SGX_SUCCESS;
    }

    ocall_println_string("[-] enclave::unsealed");

    //pretty_print_arr(unsealed, unsealed_sz, 8);

    for (uint8_t i = 0; i < num_coords; i++) {
        int idx = coords[i].x * 8 + coords[i].y;
        if (unsealed[idx] != coords[i].val) {
            *result = idx;
            return SGX_SUCCESS;
        }
    }

    *result = 1000;

    return SGX_SUCCESS;
}