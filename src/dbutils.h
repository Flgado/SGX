#include <_types/_uint32_t.h>
#include <sqlite3.h>
#include <stdio.h>
#include <sys/types.h>

/* 
 * opens database and gets a handle to it.
 * this will create the database if it doesn't exist yet.
 */
sqlite3 *open_db();
/* 
 * closes the database connection
 */
void close_database(sqlite3 *db);
/* 
 * gets the current count of client matrix cards 
 */
int32_t client_cards_count(sqlite3 *db, int32_t client_id);
/* 
 * prints result of SELECT queries to stdout
 */
int32_t print_row_callback(void *unused, int32_t count, char **values, char **columns);
/* 
 * executes sql statement
 */
int32_t execute(sqlite3 *db, const char *query, int32_t (*callback)(void*, int32_t, char**, char**), void *data);
/* 
 * inserts a new matrix card for a new client
 */
void insert_card(sqlite3 *db, int32_t client_id, const uint8_t* card);
/* 
 * prints the client card to stdout
 */
void print_client_card(sqlite3 *db, int32_t client_id);
