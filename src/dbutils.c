#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include "dbutils.h"
#include <sys/types.h>

int last_query_count = 0;

void close_database(sqlite3 *db) {
    sqlite3_close_v2(db);
}

sqlite3 *create_db_if_not_exists(char *database_name) {
    sqlite3 *db;
    char *error_msg = 0;

    int32_t sql_conn_errored = sqlite3_open(database_name, &db);

    if (sql_conn_errored) {
        fprintf(stderr, "Can't open database: %s", database_name);
        return NULL;
    }
    else {
        //fprintf(stdout, "Opened database successfully\n");
    }

    return db;
}

int32_t execute(sqlite3 *db, const char *query, int32_t (*callback)(void*, int32_t, char**, char**), void *data) {
    char *errmsg;
    int32_t rc = sqlite3_exec(db, query, callback, data, &errmsg);

    if (rc != SQLITE_OK) {
        printf("SQL error: %s\n", errmsg);
        sqlite3_free(errmsg);
    }

    return rc;
}

void try_bootstrap_db(sqlite3 *db) {
    const char *card_table_create_query = "CREATE TABLE IF NOT EXISTS card (id INTEGER PRIMARY KEY, matrix_card TEXT NOT NULL, timestamp DATETIME NOT NULL);";
    const char *log_table_create_query = "CREATE TABLE IF NOT EXISTS log (id INTEGER PRIMARY KEY, client_id INTEGER, timestamp DATETIME NOT NULL, success INTEGER NOT NULL);";

    execute(db, card_table_create_query, NULL, NULL);
    execute(db, log_table_create_query, NULL, NULL);
}

sqlite3 *open_db() {
    sqlite3 *db = create_db_if_not_exists("database.sqlite");
    try_bootstrap_db(db);

    return db;
}

void insert_card(sqlite3 *db, int32_t client_id, const uint8_t* card) {
    char query[4096];

    printf("[*] INSERT INTO card WITH VALUES (%d, *******)\n", client_id);

    snprintf(query, sizeof(query), "INSERT INTO card (id, matrix_card, timestamp) VALUES (%d, '%s', DATE('now'));", client_id, card);

    execute(db, query, NULL, NULL);
}

int32_t print_row_callback(void *unused, int32_t count, char **values, char **columns) {
    for (int32_t i = 0; i < count; i++) {
        printf("%s = %s\n", columns[i], values[i] ? values[i] : "NULL");
    }

    printf("\n");
    last_query_count = count;
    return 0;
}

int32_t print_card_callback(void *unused, int32_t count, char **values, char **columns) {
    int width = 0;
    for (int i = 0; i < 64; i++) {
        int w = snprintf(NULL, 0, "%d", (uint8_t) values[0][i]);
        if (w > width) width = w;
    }

    printf("");
    for (int i = 1; i <= 8; i++) {
        printf(" %*d", width, i);
    }
    printf("\n");

    for (int i = 0; i < 8; i++) {
        printf("%c ", 65 + i);
        for (int j = 0; j < 8; j++) {
            int index = i * 8 + j;
            printf("%*d", width, (uint8_t) values[0][index]);
            if (j < 7) printf(" ");
        }
        printf("\n");
    }

    return 0;
}

int32_t set_count_callback(void *unused, int32_t count, char **values, char **columns) {
    last_query_count = count;
    return 0;
}

int32_t client_cards_count(sqlite3 *db, int32_t client_id) {
    char query[128];
    snprintf(query, sizeof(query), "SELECT * FROM card WHERE id = %d", client_id);

    execute(db, query, set_count_callback, NULL);
    return last_query_count;
}

void print_client_card(sqlite3 *db, int32_t client_id) {
    printf("Printing client card\n");
    char query[128];
    snprintf(query, sizeof(query), "SELECT matrix_card FROM card WHERE id = %d", client_id);
    execute(db, query, print_card_callback, NULL);
}

