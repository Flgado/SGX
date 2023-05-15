#include "Enclave_t.h"
#include "sgx_trts.h"
#include "sgx_tseal.h"

#include <stdlib.h>
#include <stdio.h>
#include <string>

#include <vector>
#include <utility>
#include <cstdint>
#include <cstring>

struct Card {
    int64_t client_id;
    uint8_t matrix_data[64];
    std::vector<std::pair<uint64_t, bool>> log;
};

uint8_t *current_stored_value;

void print_values(char *format, ...) {
    char buff[128];
    va_list args;
    va_start(args, format);
    vsnprintf(buff, sizeof(buff), format, args);
    va_end(args);
    ocall_println_string(buff);
}

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

sgx_status_t unseal(uint8_t* sealed_data_ptr, size_t sealed_data_size, uint8_t** plaintext_ptr, size_t* plaintext_size_ptr, uint8_t** aad_ptr, size_t* aad_size_ptr) {
    sgx_status_t status;

    // Cast the sealed data pointer to sgx_sealed_data_t
    sgx_sealed_data_t* sealed_data = (sgx_sealed_data_t*)sealed_data_ptr;

    // Get the sizes of the aad and the plaintext
    uint32_t aad_size = sgx_get_add_mac_txt_len(sealed_data);
    uint32_t plaintext_size = sgx_get_encrypt_txt_len(sealed_data);

    // Allocate memory for the aad and the plaintext
    uint8_t* aad = (uint8_t*)malloc(aad_size);
    if(aad == NULL)
        return SGX_ERROR_OUT_OF_MEMORY;
    uint8_t* plaintext = (uint8_t*)malloc(plaintext_size);
    if(plaintext == NULL) {
        free(aad);
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    // Unseal the data
    status = sgx_unseal_data(sealed_data, aad, &aad_size, plaintext, &plaintext_size);
    if(SGX_SUCCESS != status) {
        free(aad);
        free(plaintext);
        return status;
    }

    // Return the aad and the plaintext
    *aad_ptr = aad;
    *aad_size_ptr = aad_size;
    *plaintext_ptr = plaintext;
    *plaintext_size_ptr = plaintext_size;
    return SGX_SUCCESS;
}

sgx_status_t seal(uint8_t *plaintext, size_t plaintext_len, uint8_t *aad, size_t aad_len, uint8_t **sealed_data_ptr, size_t *sealed_data_size_ptr) {
    sgx_status_t status;

    uint32_t sealed_data_size = sgx_calc_sealed_data_size((uint32_t)aad_len, (uint32_t)plaintext_len);
    if(sealed_data_size == UINT32_MAX) {
        return SGX_ERROR_UNEXPECTED;
    }

    sgx_sealed_data_t* sealed_data = (sgx_sealed_data_t*)malloc(sealed_data_size);
    if(sealed_data == NULL) {
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    status = sgx_seal_data(
        (uint32_t) aad_len, 
        aad, 
        (uint32_t) plaintext_len, 
        plaintext, 
        sealed_data_size, 
        sealed_data
    );

    if(SGX_SUCCESS != status) {
        free(sealed_data);
        return status;
    }

    *sealed_data_ptr = (uint8_t*) sealed_data;
    *sealed_data_size_ptr = sealed_data_size;
    return SGX_SUCCESS;
}

int ecall_encrypt_card(Card *card) {
    std::vector<uint8_t> serialized = serialize(*card);

    uint8_t *sealed_data = NULL;
    size_t sealed_data_size = 0;
    sgx_status_t status = seal(
        serialized.data(), 
        serialized.size(), 
        (uint8_t*)&card->client_id, 
        sizeof(card->client_id), 
        &sealed_data, 
        &sealed_data_size
    );

    if (status != SGX_SUCCESS) {
        print_values("seal failed: %d\n", status);
        return status;
    }

    // writes result into file
    int ocall_return;
    ocall_write_sealed_data(&ocall_return, card->client_id, sealed_data, sealed_data_size);
    if (ocall_return != 0) {
        print_values("Error in ocall: %d\n", ocall_return);
        return SGX_ERROR_UNEXPECTED;
    }

    free(sealed_data);
}

int generate_matrix_card_values(uint32_t client_id, uint8_t *array, size_t array_size) {
    sgx_status_t status;

    Card card;
    card.client_id = client_id;

    for (int i = 0; i < array_size; i++) {
        uint8_t value;
        status = sgx_read_rand(&value, sizeof(value));
        if (status != SGX_SUCCESS) {
            ocall_println_string("Error generating random number");
            return status;
        }
        array[i] = value;
        card.matrix_data[i] = value;
    }

    int ret = ecall_encrypt_card(&card);

    return SGX_SUCCESS; 
}

sgx_status_t ecall_validate_coords(
    uint32_t client_id, 
    Coords *coords, 
    size_t num_coords, 
    uint8_t *result, 
    uint64_t timestamp) {
    
    sgx_status_t retval = SGX_SUCCESS;
    int ret = 0;
    int ocall_return = 0;
    size_t sealed_data_size = 0;

    sgx_status_t ocall_status = ocall_get_sealed_data_size(&ocall_return, (int) client_id, &sealed_data_size);
    if (ocall_status != SGX_SUCCESS) {
        print_values("Error calling ocall: %d\n", ocall_status);
        return ocall_status;
    }
    if (ocall_return != 0) {
        print_values("Error in ocall: %d\n", ocall_return);
        return SGX_ERROR_UNEXPECTED;
    }

    uint8_t *sealed_data = (uint8_t*) malloc(sealed_data_size);
    if (sealed_data == NULL) {
        print_values("Error allocating memory for sealed data\n");
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    ocall_status = ocall_read_sealed_data(&ocall_return, (int) client_id, sealed_data, sealed_data_size);
    if (ocall_status != SGX_SUCCESS) {
        print_values("Error calling ocall: %d\n", ocall_status);
        return ocall_status;
    }
    if (ocall_return != 0) {
        print_values("Error in ocall: %d\n", ocall_return);
        return SGX_ERROR_UNEXPECTED;
    }

    uint8_t *unsealed = NULL;
    size_t unsealed_size = 0;
    uint8_t *aad = NULL;
    size_t aad_size = 0;

    retval = unseal(sealed_data, sealed_data_size, &unsealed, &unsealed_size, &aad, &aad_size);
    if (retval != SGX_SUCCESS) {
        print_values("Error unsealing data: %d\n", retval);
        return retval;
    }

    if (client_id != *(uint32_t*) aad) {
        print_values("failed signature verification\n");
        return retval;
    }

    Card card = deserialize(std::vector<uint8_t>(unsealed, unsealed + unsealed_size));

    ocall_println_string("[-] enclave::unsealed");

    *result = 1;
    for (size_t i = 0; i < num_coords; i++) {
        int idx = coords[i].y * 8 + coords[i].x;
        if (card.matrix_data[idx] != coords[i].val) {
            *result = 0;
        }
    }

    print_values("validataion result is %d\n", *result);

    card.log.push_back({timestamp, *result});

    ecall_encrypt_card(&card);

    for (const auto &entry : card.log) {
        uint64_t ts = (uint64_t) entry.first;
        bool validation_result = (bool) entry.second;

        char buffer[1000];
        snprintf(buffer, sizeof(buffer), "\t [+] timestamp: %lu, validation result: %d", ts, validation_result);
        ocall_println_string(buffer);
    }

    free(sealed_data);
    free(unsealed);
    free(aad);

    return retval; 
}