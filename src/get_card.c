#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include "dbutils.h"

void usage(char *program_name) {
    printf("usage: %s <client_id>\n", program_name);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        usage(argv[0]);
        return 0;
    }

    sqlite3 *db = open_db();

    int client_id = atoi(argv[1]);

    print_client_card(db, client_id);

    return 0;
}
