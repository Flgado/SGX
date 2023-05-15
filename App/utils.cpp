#include "utils.h"

#include <string>
#include <iostream>
#include <stdio.h>
#include <iostream>
#include <iomanip>
#include <string>
#include "Enclave_u.h"

void print_usage(char const *argv[]) {
    printf("usage: %s [--generate | --validate <client_id> <coords>]\n", argv[0]);
    printf("\n--generate:  generates a new client matrix card, showing it alongside the newly created client ID");
    printf("\n--validate:  <client_id> <coords>  validates coords against the client's matrix card. \n");
    printf("             coords should be of type: a0=1,a2=10,a3=20\n");
}

void pretty_print_arr(const uint8_t *data, size_t size, size_t max_per_line) {
    for (size_t i = 0; i < size; ++i) {
        if (i == 0) {
            std::cout << "\t";
        }
        std::cout << std::setw(3) << std::setfill('0') << std::dec << static_cast<int>(data[i]) << ' ';

        if ((i + 1) % max_per_line == 0) {
            std::cout << std::endl
                      << "\t";
        }
    }
    std::cout << std::dec << std::endl;
}

int parse_coords(char const *input, struct Coords **coords_arr) {
    int count = 0;

    const char *ptr = input;

    while ((ptr = strchr(ptr, '=')) != NULL) {
        count++;
        ptr++;
    }

    *coords_arr = (struct Coords *)malloc(count * sizeof(struct Coords));
    if (!*coords_arr) {
        printf("error while parsing coordinates\n");
        exit(1);
    }

    int index = 0;
    ptr = input;
    while (sscanf(ptr, "%c%hhu=%hhu", &((*coords_arr)[index].y), &((*coords_arr)[index].x), &((*coords_arr)[index].val)) == 3) {
        (*coords_arr)[index].y = toupper((*coords_arr)[index].y) - 'A';

        ptr = strchr(ptr, ',');

        if (!ptr) {
            break;
        }

        ptr++;
        index++;
    }

    return count;
}