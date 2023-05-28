#include "utils.h"

#include <string>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <dirent.h>
#include <stdarg.h>

#include "Enclave_u.h"

void print_usage(char *argv[]) {
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

    printf("\n\n*** Coordinates are passed in strings like 'a0:1=2', where:\n");
    printf("     - 'a0' determines the coordinates in the matrix, from 'a' to 'h' and '0' to '7'\n");
    printf("     - :1 determines the index of the digit we want to compare (1-3)\n");
    printf("     - =2 determines the value we want to compare the digit against\n");
    printf("     - Basically, if the challenge is 'give me the third number in position b5', \n       we would pass something like 'b5:3=<client_response>'\n");
    printf("     - Multiple coordinates can be passed, separated by ',', e.g; a0:1=9,c7:2=1,d1:3=3\n");

    printf("\nExamples:\n");
    printf(" Setup a new client card, for client identifier 1\n");
    printf("   %s --setup 1\n", argv[0]);
    printf(" Validate coordinate values (a, 0, 1) = 1, (b, 0, 3) = 2 for client 1\n");
    printf("   %s --validate 1 a0:1=1,b0:3=2\n", argv[0]);
    printf(" Print access logs for client 1\n");
    printf("   %s --logs 1\n", argv[0]);
    printf(" Show existing cards for enclave with version 2\n");
    printf("   %s --card-versions 2\n", argv[0]);
    printf(" Migrate cards from enclave src into enclave dst's version\n");
    printf("   %s --migrate src.signed.so dst.signed.so\n", argv[0]);
    printf(" Run --logs, --setup, --validate with specific enclave's binary\n");
    printf("   %s [...] --binary your.enclave.binary.so\n", argv[0]);

    printf("\n*** If you want to run with --binary, it needs to be the first argument!\n");
}

void print_red(char *format, ...) {
    char buff[128];
    va_list args;
    va_start(args, format);
    vsnprintf(buff, sizeof(buff), format, args);
    va_end(args);
    printf("\033[0;31m%s\033[0;0m", buff);
}

void print_yellow(char *format, ...) {
    char buff[128];
    va_list args;
    va_start(args, format);
    vsnprintf(buff, sizeof(buff), format, args);
    va_end(args);
    printf("\033[0;33m%s\033[0;0m", buff);
}

void print_green(char *format, ...) {
    char buff[128];
    va_list args;
    va_start(args, format);
    vsnprintf(buff, sizeof(buff), format, args);
    va_end(args);
    printf("\033[0;32m%s\033[0;0m", buff);
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
    while (sscanf(
        ptr, "%c%hhu:%hhu=%hhu", 
        &((*coords_arr)[index].y), 
        &((*coords_arr)[index].x), 
        &((*coords_arr)[index].pos), 
        &((*coords_arr)[index].val)) == 4) {

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

int is_number(const char *str) {
    while (*str != '\0') {
        if (!isdigit((unsigned char)* str)) {
            return 0; 
        }
        str++;
    }

    return 1;
}

char **get_file_names_for_enclave_version(uint8_t version, int *count) {
    char **file_names = NULL;
    *count = 0;

    DIR *dir = opendir("cards");
    if (dir == NULL) {
        printf("* unable to open directory 'cards'\n");
        return NULL;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (!is_number(entry->d_name)) {
            continue;
        }

        char file_name[500];
        snprintf(file_name, sizeof(file_name), "cards/%s", entry->d_name);
        FILE *file = fopen(file_name, "rb");

        if (file == NULL) {
            printf("* unable to open file: %s\n", file_name);
            continue;
        }

        fseek(file, -1, SEEK_END);
        unsigned char last_byte;
        fread(&last_byte, 1, 1, file);
        if (last_byte == version) {
            file_names = (char**) realloc(file_names, (*count + 1) * sizeof(char*));
            file_names[*count] = (char*) malloc(strlen(entry->d_name) + 1);
            strcpy(file_names[*count], entry->d_name);
            (*count)++;
        }

        fclose(file);
    }

    closedir(dir); 

    return file_names;
}
