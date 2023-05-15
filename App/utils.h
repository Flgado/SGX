#ifndef UTILS_H_
#define UTILS_H_

#include <sys/types.h>
#include <string>

void pretty_print_arr(const uint8_t *data, size_t size, size_t max_per_line); 
int parse_coords(char const *input, struct Coords **coords_arr);
void print_usage(char const *argv[]);

#endif
