#include "Enclave_t.h"
#include "sgx_trts.h"
#include "sgx_tseal.h"

#include <stdlib.h>
#include <stdio.h>
#include <sqlite3.h>
#include <string>

#include <vector>
#include <utility>
#include <cstdint>
#include <cstring>

struct Card {
    int64_t client_id;
    uint8_t matrix_data[64];
    std::vector<std::pair<uint64_t, bool>> log;
};

sqlite3 *db;

uint8_t *current_stored_value;

void bootstrap_persistence() {
    ecall_opendb("matrix_cards.db");
    const char *card_table_create_query = 
        "CREATE TABLE IF NOT EXISTS card (\
            id INTEGER PRIMARY KEY AUTOINCREMENT, \
            matrix_data BLOB NOT NULL \
        );";

    ecall_execute_sql(card_table_create_query);
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
    //ocall_print_string("Enclave: Created database connection to ");
    //ocall_println_string(dbname);
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

void update_matrix_card(uint8_t *data, uint32_t data_size, uint32_t client_id) {
    //boostrap_persistence();
    char query[128];
    snprintf(query, sizeof(query), "UPDATE card SET matrix_data = ? WHERE id = %d", client_id);

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, query, -1, &stmt, 0);

    rc = sqlite3_bind_blob(stmt, 1, data, data_size, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

void ecall_insert_matrix_card(uint8_t *data, uint32_t data_size) {
    bootstrap_persistence();
    const char *insert_stmt = "INSERT INTO card (matrix_data) VALUES (?);";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, insert_stmt, -1, &stmt, 0);

    rc = sqlite3_bind_blob(stmt, 1, data, data_size, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    char query[100];
    snprintf(query, sizeof(query), "\tnew_client_id = %ld", (int64_t) sqlite3_last_insert_rowid(db));
    ocall_println_string(query);
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

    sgx_sealed_data_t *sgx_sealed = (sgx_sealed_data_t*) malloc(sealed_data_size_needed);
    ret = sgx_seal_data(0, nullptr, plaintext_size, plaintext, sealed_data_size_needed, sgx_sealed);

    memcpy(sealed_data, sgx_sealed, sealed_data_size_needed);

    if (ret != SGX_SUCCESS) {
        return ret;
    }

    free(sgx_sealed);

    return SGX_SUCCESS;
}

sgx_status_t unseal_data(uint8_t* sealed_data, uint8_t* plaintext, size_t plaintext_size) {
    sgx_status_t ret = SGX_SUCCESS;

    if (sealed_data == NULL || plaintext == NULL) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    uint32_t plaintext_size_needed = sgx_get_encrypt_txt_len((sgx_sealed_data_t*)sealed_data);

    if (plaintext_size_needed != plaintext_size) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    ret = sgx_unseal_data((sgx_sealed_data_t*)sealed_data, nullptr, 0, plaintext, &plaintext_size_needed);

    if (ret != SGX_SUCCESS) {
        return ret;
    }

    return SGX_SUCCESS;
}

Card deserialize(const std::vector<uint8_t>& serialized) {
    Card card;
    size_t pos = 0;

    // deserialize client_id
    std::memcpy(&card.client_id, &serialized[pos], sizeof(int64_t));
    pos += sizeof(int64_t);

    // deserialize matrix_data
    std::memcpy(card.matrix_data, &serialized[pos], 64);
    pos += 64;

    // deserialize log
    uint32_t num_log_entries;
    std::memcpy(&num_log_entries, &serialized[pos], sizeof(uint32_t));
    pos += sizeof(uint32_t);

    for (uint32_t i = 0; i < num_log_entries; i++) {
        std::pair<uint64_t, bool> log_entry;
        std::memcpy(&log_entry.first, &serialized[pos], sizeof(uint64_t));
        pos += sizeof(uint64_t);
        std::memcpy(&log_entry.second, &serialized[pos], sizeof(bool));
        pos += sizeof(bool);
        card.log.push_back(log_entry);
    }

    return card;
}

std::vector<uint8_t> serialize(const Card& card) {
    size_t total_size = sizeof(card.client_id) + sizeof(card.matrix_data) + sizeof(card.log.size());

    for (const auto& entry : card.log) {
        total_size += sizeof(entry.first) + sizeof(entry.second);
    }

    std::vector<uint8_t> serialized_card(total_size);

    // Start copying data
    size_t offset = 0;

    // Copy client_id
    memcpy(serialized_card.data() + offset, &card.client_id, sizeof(card.client_id));
    offset += sizeof(card.client_id);

    // Copy matrix_data
    memcpy(serialized_card.data() + offset, &card.matrix_data, sizeof(card.matrix_data));
    offset += sizeof(card.matrix_data);

    // Copy log
    size_t size = card.log.size();
    memcpy(serialized_card.data() + offset, &size, sizeof(size));
    offset += sizeof(size);
    for (const auto& entry : card.log) {
        memcpy(serialized_card.data() + offset, &entry.first, sizeof(entry.first));
        offset += sizeof(entry.first);
        memcpy(serialized_card.data() + offset, &entry.second, sizeof(entry.second));
        offset += sizeof(entry.second);
    }

    return serialized_card;
}

int generate_matrix_card_values(uint8_t *array, size_t array_size) {
    sgx_status_t status;

    bootstrap_persistence();

    int64_t last_id = (int64_t) sqlite3_last_insert_rowid(db);
    Card card;
    card.client_id = last_id + 1;

    for (int i = 0; i < array_size; i++) {
        uint8_t value;
        status = sgx_read_rand(&value, sizeof(value));
        if (status != SGX_SUCCESS) {
            ocall_println_string("Error generating random number: ");
            return status;
        }
        array[i] = value;
        card.matrix_data[i] = value;
    }

    char query[100];

    std::vector<uint8_t> serialized = serialize(card);
    uint32_t sealed_data_size = get_sealed_data_size(serialized.size());

    snprintf(query, sizeof(query), "sealed 1 %d", sealed_data_size);
    ocall_println_string(query);

    uint8_t *sealed = new uint8_t[sealed_data_size];

    uint8_t *serialized_ptr = serialized.data();

    status = seal_data(serialized_ptr, serialized.size(), sealed, sealed_data_size);
    if (status != SGX_SUCCESS) {
        ocall_println_string("Error sealing data: ");
        delete[] sealed;
        return status;
    }

    const char *insert_stmt = "INSERT INTO card (matrix_data) VALUES (?);";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, insert_stmt, -1, &stmt, 0);

    if (rc != SQLITE_OK) {
        ocall_println_string("Error preparing statement: ");
        delete[] sealed;
        return rc;
    }

    rc = sqlite3_bind_blob(stmt, 1, sealed, sealed_data_size, SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        ocall_println_string("Error binding blob: ");
        sqlite3_finalize(stmt);
        delete[] sealed;
        return rc;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        ocall_println_string("Error executing statement: ");
        sqlite3_finalize(stmt);
        delete[] sealed;
        return rc;
    }

    sqlite3_finalize(stmt);
    delete[] sealed;

    snprintf(query, sizeof(query), "\tnew_client_id = %ld, sealed data size = %d", (int64_t) sqlite3_last_insert_rowid(db), sealed_data_size);
    ocall_println_string(query);

    ecall_close_db();
    return SGX_SUCCESS;
}

sgx_status_t ecall_validate_coords(uint32_t client_id, Coords *coords, size_t num_coords, uint8_t *result, uint64_t timestamp) {
    char query[128];
    snprintf(query, sizeof(query), "SELECT matrix_data FROM card WHERE id = %d", client_id);
    
    int size = 0;
    sgx_status_t retval = SGX_SUCCESS;

    bootstrap_persistence();

    ecall_get_text_size(query, &size);

    uint8_t *sealed_from_db = new uint8_t[size];
    ecall_get_text_value(query, sealed_from_db, size);

    ocall_println_string("\n[-] enclave::seal_from_db");
    ocall_println_string("[-] enclave::unsealing");

    uint32_t unsealed_sz = sgx_get_encrypt_txt_len((sgx_sealed_data_t*)sealed_from_db);
    uint8_t* unsealed = (uint8_t*)malloc(unsealed_sz);

    int ret = unseal_data(sealed_from_db, unsealed, unsealed_sz);

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

    Card card = deserialize(std::vector<uint8_t>(unsealed, unsealed + unsealed_sz));

    ocall_println_string("[-] enclave::unsealed");

    *result = 1;
    for (size_t i = 0; i < num_coords; i++) {
        int idx = coords[i].y * 8 + coords[i].x;
        if (card.matrix_data[idx] != coords[i].val) {
            *result = 0;
            goto break_loop;
        }
    }
    break_loop:

    std::pair<uint64_t, bool> new_log_entry = std::make_pair((uint64_t) timestamp, (bool)*result);
    card.log.push_back(new_log_entry);

    std::vector<uint8_t> serialized = serialize(card);
    uint32_t sealed_data_size = get_sealed_data_size(serialized.size());
    uint8_t *sealed = new uint8_t[sealed_data_size];
    uint8_t *serialized_ptr = serialized.data();

    seal_data(serialized_ptr, serialized.size(), sealed, sealed_data_size);

    update_matrix_card(sealed, sealed_data_size, (uint32_t) client_id);

    for (const auto &entry : card.log) {
        uint64_t timestamp = entry.first;
        bool result = entry.second;

        char buffer[128];
        snprintf(buffer, sizeof(buffer), "\t [+] timestamp: %lu, validation result: %d", timestamp, result);
        ocall_println_string(buffer);
    }

    return SGX_SUCCESS;
}