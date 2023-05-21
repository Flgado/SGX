#include "sgx_tcrypto.h"
#include "Enclave_t.h"
#include "sgx_trts.h"
#include "sgx_tseal.h"

#include "serializer.h"

#include <stdlib.h>
#include <stdio.h>
#include <string>

#include <vector>
#include <utility>
#include <cstdint>
#include <cstring>
#include "encryption.h"

uint8_t enclave_key[KEY_SIZE];
sgx_status_t ecall_generate_key(uint8_t* key, size_t key_size) {
    if (key_size != KEY_SIZE) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    sgx_read_rand(key, key_size);
    for(int i = 0; i < KEY_SIZE; i++) {
        enclave_key[i] = key[i];
    }

    return SGX_SUCCESS;
}

sgx_status_t decrypt_data(uint8_t* ciphertext, size_t ciphertext_size, uint8_t* tag) {
    uint8_t plaintext[ciphertext_size];

    sgx_aes_gcm_128bit_key_t aes_key;
    memcpy(aes_key, enclave_key, KEY_SIZE);

    uint8_t *iv = (uint8_t *) calloc(IV_SIZE, sizeof(uint8_t));

    sgx_status_t status = sgx_rijndael128GCM_decrypt(&aes_key, ciphertext, ciphertext_size, ciphertext, iv, IV_SIZE, NULL, 0, (sgx_aes_gcm_128bit_tag_t*)tag);
    return status;
}