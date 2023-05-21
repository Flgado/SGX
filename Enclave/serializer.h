#ifndef SERIALIZER_H_
#define SERIALIZER_H_

#include <vector>

struct Card {
    int64_t client_id;
    uint8_t matrix_data[64];
    std::vector<std::pair<uint64_t, bool>> log;
};

Card deserialize(const std::vector<uint8_t>& serialized);
std::vector<uint8_t> serialize(const Card& card);

#endif