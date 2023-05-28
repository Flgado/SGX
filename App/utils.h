#ifndef UTILS_H_
#define UTILS_H_

#include <sys/types.h>
#include <string>

int parse_coords(char const *input, struct Coords **coords_arr);
void print_usage(char *argv[]);
char **get_file_names_for_enclave_version(uint8_t version, int *count);
void print_red(char *format, ...);
void print_yellow(char *format, ...);
void print_green(char *format, ...);

#endif
