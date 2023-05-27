#include "utils.h"

#include <string>
#include <iostream>
#include <stdio.h>
#include <iostream>
#include <iomanip>
#include <string>
#include "Enclave_u.h"

void print_usage(char const *argv[]) {
    printf("Usage: %s [OPTION]\n\n", argv[0]);
    printf("Authors:\n");
    printf(" Marcos Caramalho\n");
    printf(" João Folgado\n\n");
    printf("Options:\n");
    printf(" --help                           Show this help screen\n");
    printf(" --setup <client_id>              Sets up a new card for provided <client_id>\n");
    printf(" --validate <client_id> <coords>  Validates provided coordinates for client card\n");
    printf(" --migrate <src> <dst>            Migrate cards from source enclave version to destination\n");
    printf(" --card-versions <version>        Get a list of cards for a specific enclave version\n");
    printf(" --logs <client_id>               Prints logs for client matrix card accesses\n");
    printf(" --binary <binary>                Use specific binary\n");

    printf(" * By default, the enclave used is found in enclave.signed.so\n");
    printf(" * If needed, we can use the --binary option to specify a different one\n");

    printf("\nExamples:\n");
    printf(" Setup a new client card, for client identifier 1\n");
    printf("   %s --setup 1\n", argv[0]);
    printf(" Validate coordinate values (a, 0) = 10, (b, 0) = 20 for client 1\n");
    printf("   %s --validate 1 a0=10,b0=20\n", argv[0]);
    printf(" Print access logs for client 1\n");
    printf("   %s --logs 1\n", argv[0]);
    printf(" Show existing cards for enclave with version 2\n");
    printf("   %s --card-versions 2\n", argv[0]);
    printf(" Migrate cards from enclave src into enclave dst's version\n");
    printf("   %s --migrate src.signed.so dst.signed.so\n", argv[0]);
    printf(" Run --logs, --setup, --validate with specific enclave's binary\n");
    printf("   %s [...] --binary your.enclave.binary.so\n", argv[0]);
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