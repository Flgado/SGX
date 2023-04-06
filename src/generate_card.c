#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include "dbutils.h"

#define MATRIX_CARD_SIZE 64

uint8_t *get_random_buf(size_t size) {
  int fd = open("/dev/urandom", O_RDONLY);
  if (fd < 0) {
    perror("Failed to open /dev/urandom");
    return NULL;
  }

  // Buffer size
  uint8_t *buffer = (uint8_t*) malloc(size);

  ssize_t bytes_read = read(fd, buffer, size);
  if (bytes_read != size) {
    perror("Failed to read from /dev/urandom");
    close(fd);
    return NULL;
  }

  close(fd);

  for (size_t i = 0; i < size; i++) {
    buffer[i] = (buffer[i] % 254) + 1; // Values in range 1-254
    //printf("%u\n", buffer[i]);
  }

  return buffer;
}

void usage(char *prog_name) {
    printf("Program usage:\n");
    printf("\t%s <client id>\n", prog_name);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        usage(argv[0]);
        return 0;
    }

    sqlite3 *db = open_db();

    printf("Querying for clients inside generator...\n");

    int client_id = atoi(argv[1]);
    int count = client_cards_count(db, client_id);

    if (count > 0) {
        printf("A client for the identifier %d already exists, use a different identifier\n", client_id);
        return 1;
    }

    printf("Creating card for client %s\n", argv[1]);
    uint8_t *card = get_random_buf(MATRIX_CARD_SIZE);

    insert_card(db, client_id, card);
    print_client_card(db, client_id);

    free(card);

    return 0;
}
