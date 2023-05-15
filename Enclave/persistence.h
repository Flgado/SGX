#ifndef UTILS_H_
#define UTILS_H_

#include <sqlite3.h>
#include <cstdint>

int get_card_sealed_size(uint32_t client_id);
void print_values(char *format, ...);

#endif