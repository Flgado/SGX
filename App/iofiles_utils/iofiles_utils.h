#ifndef IOFILES_UTILS_H_
#define IOFILES_UTILS_H_

#include <sstream>

bool write_seal_data(const uint8_t* sealed_data, size_t sealed_size, int identifier);

bool read_seal_data(int identifier, uint8_t* sealed_data_array, size_t array_size);

#endif // IOFILES_UTILS_H_