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

static int callback(void *NotUsed, int argc, char **argv, char **azColName) {
    for (int i = 0; i < argc; i++) {
        std::string azColName_str = azColName[i];
        std::string argv_str = (argv[i] ? argv[i] : "NULL");
        ocall_print_string((azColName_str + " = " + argv_str + "\n").c_str());
    }
    ocall_print_string("\n");
    return 0;
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

void ecall_open_db(const char *dbname) {
    if (db != NULL) {
        ocall_println_string("db already instantiated");
        return;
    }

    int rc = sqlite3_open_v2(dbname, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nullptr); 
    if (rc != SQLITE_OK) {
        ocall_println_string("SQLite error - can't open database connection: ");
        ocall_println_string(sqlite3_errmsg(db));
        return;
    }
    ocall_println_string(dbname);

    rc = sqlite3_busy_timeout(db, 5000);
    if (rc != SQLITE_OK) {
        ocall_println_string(sqlite3_errmsg(db));
    }

    char *err_msg = 0;
    rc = sqlite3_exec(db, "PRAGMA locking_mode = NORMAL; PRAGMA threads=10; PRAGMA read_uncommited = true", NULL, 0, &err_msg);
    if (rc != SQLITE_OK) {
        ocall_println_string(sqlite3_errmsg(db));
    }
}

void open_db() {
    ecall_open_db("matrix_cards.db");
    ocall_println_string("opened connection");
}

void print_values(char *format, ...) {
    char buff[128];
    va_list args;
    va_start(args, format);
    vsnprintf(buff, sizeof(buff), format, args);
    va_end(args);
    ocall_println_string(buff);
}

void close_db() {
    int rc = sqlite3_close(db);
    print_values("closing db connection, close result %d", rc);
    db = nullptr;
}

void bootstrap_persistence() {
    open_db();
    const char *card_table_create_query = 
        "CREATE TABLE IF NOT EXISTS card (\
            id INTEGER PRIMARY KEY AUTOINCREMENT, \
            matrix_data BLOB \
        );";

    ecall_execute_sql(card_table_create_query);
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

std::string to_hex_string(const uint8_t* data, size_t data_size) {
    static const char hex_chars[] = "0123456789ABCDEF";
    std::string hex_str;
    hex_str.reserve(data_size * 2);  // Each byte will become 2 hex chars

    for (size_t i = 0; i < data_size; ++i) {
        uint8_t byte = data[i];
        hex_str.push_back(hex_chars[byte >> 4]);  // High nibble
        hex_str.push_back(hex_chars[byte & 0x0F]);  // Low nibble
    }

    return hex_str;
}

void update_matrix_card(uint8_t *data, uint32_t data_size, uint32_t client_id) {
    int rc = 0;
    char *err_msg = 0;

    //rc = sqlite3_exec(db, "PRAGMA locking_mode = EXLUSIVE;", NULL, 0, &err_msg);
    //if (rc != SQLITE_OK) {
    //    print_values("sqlite3_exec PRAGMA locking_mode %d, %s", rc, sqlite3_errmsg(db));
    //    ocall_println_string(sqlite3_errmsg(db));
    //}

    rc = sqlite3_busy_timeout(db, 5000);
    if (rc != SQLITE_OK) {
        ocall_println_string(sqlite3_errmsg(db));
        return;  // Return early as setting timeout failed.
    }

    rc = sqlite3_exec(db, "BEGIN EXCLUSIVE TRANSACTION;", NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        int extended_err = sqlite3_extended_errcode(db);
        print_values("sqlite3_exec(BEGIN EXCLUSIVE TRANSACTION) -- rc: %d, ex: %d, err: %s", rc, extended_err, sqlite3_errmsg(db));
        sqlite3_free(err_msg);
        return;  // Return early as transaction start failed.
    }

    const char *update_stmt = "UPDATE card SET matrix_data = ? WHERE id = ?;";

    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(db, update_stmt, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) { 
        ocall_println_string("SQLITE_OK fail prepare");
        return;  // Return early as statement prepare failed.
    }

    rc = sqlite3_bind_int(stmt, 2, client_id);
    if (rc != SQLITE_OK) { 
        ocall_println_string("SQLITE_OK fail bind int64");
        sqlite3_finalize(stmt);
        return;  // Return early as bind int failed.
    }

    rc = sqlite3_bind_blob(stmt, 1, data, data_size, SQLITE_STATIC);
    if (rc != SQLITE_OK) { 
        ocall_println_string("SQLITE_OK fail bind blob");
        sqlite3_finalize(stmt);
        return;  // Return early as bind blob failed.
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) { 
        int extended_err = sqlite3_extended_errcode(db);
        print_values("sqlite3_step() -- rc: %d, ex: %d, err: %s", rc, extended_err, sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        //sqlite3_exec(db, "ROLLBACK;", NULL, NULL, &err_msg);  // Rollback transaction in case of failure.
        return;  // Return early as statement execution failed.
    }

    rc = sqlite3_exec(db, "COMMIT;", NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        //print_values("transaction error, %d, %s", rc, err_msg);
        sqlite3_free(err_msg);
    }

    sqlite3_finalize(stmt);

    //*err_msg = 0;
    //rc = sqlite3_exec(db, "COMMIT;", NULL, NULL, &err_msg);
    //if (rc != SQLITE_OK) {
    //    ocall_println_string(err_msg);
    //    sqlite3_free(err_msg);
    //}
    //char buf[128];
    //snprintf(buf, sizeof(buf), "card size inserted = %d, for id = %d", data_size, client_id);
    //ocall_println_string(buf);
}

void ecall_get_text_size(const char *sql, int *size) {
    sqlite3_stmt *stmt;

    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
    if (rc != SQLITE_OK) {
        *size = -1;
        ocall_println_string(sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return;
    }

    if ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        const void *blob_data = sqlite3_column_blob(stmt, 0);
        if (blob_data) { 
            *size = sqlite3_column_bytes(stmt, 0);
        }
        else {
            *size = -1;
        }
    }
    else {
        *size = -1;
    }

    sqlite3_finalize(stmt);
}

void get_card_from_db(uint32_t client_id, uint8_t *card) {
    close_db();
    open_db();
    const char *sql = "SELECT matrix_data FROM card WHERE id = ?";
    sqlite3_stmt *stmt;

    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);

    rc = sqlite3_bind_int(stmt, 1, client_id);
    if (rc != SQLITE_OK) {
        ocall_println_string(sqlite3_errmsg(db));
    }

    int sz;
    if ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        sz = sqlite3_column_bytes(stmt, 0);
        const void *blob_data = sqlite3_column_blob(stmt, 0);

        if (blob_data) {
            memcpy(card, blob_data, sz);
        }
    }
    else {
        ocall_println_string(sqlite3_errmsg(db));
    }
    sqlite3_finalize(stmt);
}

void ecall_get_text_value(const char *sql, uint8_t *data_from_db, uint32_t data_from_db_size) {
    sqlite3_stmt *stmt;

    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
    if (rc != SQLITE_OK) {
        ocall_println_string(sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return;
    }

    if ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        const void *blob_data = sqlite3_column_blob(stmt, 0);
        if (blob_data) {
            int sz = sqlite3_column_bytes(stmt, 0);
            if (sz > data_from_db_size) {
                ocall_println_string("buffer size provided is not large enough");
                sqlite3_finalize(stmt);
                return;
            }
            memcpy(data_from_db, blob_data, sz);
        }
    } else {
        ocall_println_string("step did not result in a row (SQLITE_DONE or error)");
    }

    sqlite3_finalize(stmt);
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
    //print_values("%d\n", sealed_data_size_needed);

    if (sealed_size < sealed_data_size_needed) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    //print_values("%d\n", plaintext_size);

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

template <typename T>
void read_from_vector(const std::vector<uint8_t>& vec, size_t& offset, T& value) {
    memcpy(&value, vec.data() + offset, sizeof(T));
    offset += sizeof(T);
}

Card deserialize(const std::vector<uint8_t>& serialized) {
    Card card;
    size_t offset = 0;

    // Read client_id
    read_from_vector(serialized, offset, card.client_id);

    // Read matrix_data
    for (auto& data : card.matrix_data) {
        read_from_vector(serialized, offset, data);
    }

    // Read log
    size_t size;
    read_from_vector(serialized, offset, size);
    card.log.resize(size);
    for (auto& entry : card.log) {
        read_from_vector(serialized, offset, entry.first);
        read_from_vector(serialized, offset, entry.second);
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
    bootstrap_persistence();

    sgx_status_t status;

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
        sqlite3_finalize(stmt);
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
        ocall_println_string(sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        delete[] sealed;
        return rc;
    }

    sqlite3_finalize(stmt);
    delete[] sealed;

    snprintf(query, sizeof(query), "\tnew_client_id = %ld, sealed data size = %d", (int64_t) sqlite3_last_insert_rowid(db), sealed_data_size);
    ocall_println_string(query);

    return SGX_SUCCESS;
}

sgx_status_t ecall_validate_coords(uint32_t client_id, Coords *coords, size_t num_coords, uint8_t *result, uint64_t timestamp) {
    bootstrap_persistence();

    sgx_status_t retval = SGX_SUCCESS;
    int ret = 0;

    print_values("---- ecall_validate_coords :: client_id = %d, timestamp = %d\n", client_id, timestamp);

    // query for data
    char query[1000];
    snprintf(query, sizeof(query), "SELECT matrix_data FROM card WHERE id = %d", client_id);
    int matrix_data_size = 0;

    ocall_println_string("calling ecall_get_text_size");
    ecall_get_text_size(query, &matrix_data_size);

    uint8_t *data_from_db = (uint8_t*) malloc (sizeof(uint8_t) * matrix_data_size);
    print_values("calling ecall_get_text_value, size = %d", matrix_data_size);
    get_card_from_db(client_id, data_from_db);
    print_values("called get_card_from_db");

    // unseal data 
    ocall_println_string("\n[-] enclave::seal_from_db");
    ocall_println_string("[-] enclave::unsealing");
    uint32_t unsealed_sz = sgx_get_encrypt_txt_len((sgx_sealed_data_t*) data_from_db); 
    uint8_t *unsealed = (uint8_t*) malloc(unsealed_sz * sizeof(uint8_t));

    ret = unseal_data(data_from_db, unsealed, unsealed_sz);

    Card card = deserialize(std::vector<uint8_t>(unsealed, unsealed + unsealed_sz));

    ocall_println_string("[-] enclave::unsealed");

    *result = 1;
    for (size_t i = 0; i < num_coords; i++) {
        int idx = coords[i].y * 8 + coords[i].x;
        if (card.matrix_data[idx] != coords[i].val) {
            *result = 0;
        }
    }

    card.log.push_back({timestamp, *result});

    std::vector<uint8_t> serialized = serialize(card);
    uint32_t sealed_data_size = get_sealed_data_size(serialized.size());

    uint8_t *sealed = (uint8_t*) malloc(sealed_data_size * sizeof(uint8_t));
    uint8_t *serialized_ptr = serialized.data();
    seal_data(serialized_ptr, serialized.size(), sealed, sealed_data_size);

    update_matrix_card(sealed, sealed_data_size, client_id);

    free(sealed);

    for (const auto &entry : card.log) {
        uint64_t ts = (uint64_t) entry.first;
        bool result = (bool) entry.second;

        char buffer[1000];
        snprintf(buffer, sizeof(buffer), "\t [+] timestamp: %lu, validation result: %d", ts, result);
        ocall_println_string(buffer);
    }

    close_db();

    return SGX_SUCCESS;
}