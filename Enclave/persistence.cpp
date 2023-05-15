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

void print_values(char *format, ...) {
    char buff[128];
    va_list args;
    va_start(args, format);
    vsnprintf(buff, sizeof(buff), format, args);
    va_end(args);

    ocall_print(buff);
}

int get_card_sealed_size(uint32_t client_id) {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    int rc;

    rc = sqlite3_open("client_cards.db", &db);
    if (rc != SQLITE_OK) {
        print_values("cannot open database: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    rc = sqlite3_prepare_v2(
        db, 
        "SELECT matrix_data FROM card WHERE id = ?", 
        -1, 
        &stmt, 
        nullptr
    );

    if (rc != SQLITE_OK) {
        print_values("failed to prepare statement: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    rc = sqlite3_bind_int(stmt, client_id, 1); 
    if (rc != SQLITE_OK) {
        print_values("failed to bind value: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        int blob_size = sqlite3_column_bytes(stmt, 0);
        print_values("Size of the blob is: %d bytes\n", blob_size);
        return blob_size;
    } else {
        print_values("No such row or an error occurred: %s\n", sqlite3_errmsg(db));
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);

    return -1;
}