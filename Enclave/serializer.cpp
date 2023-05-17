#include "Enclave_t.h"

#include <vector>
#include <utility>
#include <cstdint>
#include <cstring>

#include "serializer.h"

template <typename T>
void read_from_vector(const std::vector<uint8_t>& vec, size_t& offset, T& value) {
    memcpy(&value, vec.data() + offset, sizeof(T));
    offset += sizeof(T);
}

Card deserialize(const std::vector<uint8_t>& serialized) {
    Card card;
    size_t offset = 0;

    // Read client_id
    read_from_vector(serialized, offset, card.client_id);

    // Read matrix_data
    for (auto& data : card.matrix_data) {
        read_from_vector(serialized, offset, data);
    }

    // Read log
    size_t size;
    read_from_vector(serialized, offset, size);
    card.log.resize(size);
    for (auto& entry : card.log) {
        read_from_vector(serialized, offset, entry.first);
        read_from_vector(serialized, offset, entry.second);
    }

    return card;
}

std::vector<uint8_t> serialize(const Card& card) {
    size_t total_size = sizeof(card.client_id) + sizeof(card.matrix_data) + sizeof(card.log.size());

    for (const auto& entry : card.log) {
        total_size += sizeof(entry.first) + sizeof(entry.second);
    }

    std::vector<uint8_t> serialized_card(total_size);

    // Start copying data
    size_t offset = 0;

    // Copy client_id
    memcpy(serialized_card.data() + offset, &card.client_id, sizeof(card.client_id));
    offset += sizeof(card.client_id);

    // Copy matrix_data
    memcpy(serialized_card.data() + offset, &card.matrix_data, sizeof(card.matrix_data));
    offset += sizeof(card.matrix_data);

    // Copy log
    size_t size = card.log.size();
    memcpy(serialized_card.data() + offset, &size, sizeof(size));
    offset += sizeof(size);
    for (const auto& entry : card.log) {
        memcpy(serialized_card.data() + offset, &entry.first, sizeof(entry.first));
        offset += sizeof(entry.first);
        memcpy(serialized_card.data() + offset, &entry.second, sizeof(entry.second));
        offset += sizeof(entry.second);
    }

    return serialized_card;
}