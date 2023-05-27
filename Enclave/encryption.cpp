#include "sgx_tcrypto.h"
#include "Enclave_t.h"
#include "sgx_trts.h"
#include "sgx_tseal.h"

#include "headers/serializer.h"

#include <stdlib.h>
#include <stdio.h>
#include <string>

#include <vector>
#include <utility>
#include <cstdint>
#include <cstring>
#include "headers/encryption.h"
#include "headers/utils.h"

#include "headers/sign.h"

uint8_t enclave_key[KEY_SIZE];
sgx_status_t ecall_generate_key(
    uint8_t* key, 
    size_t key_size, 
    ECDSA256Signature* enclave_signature, 
    size_t signature_size) {

    if (key_size != KEY_SIZE) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    sgx_read_rand(key, key_size);
    for(int i = 0; i < KEY_SIZE; i++) {
        enclave_key[i] = key[i];
    }
    uint8_t *sign_arr = (uint8_t *)malloc(key_size);
    memcpy(sign_arr, (uint8_t*)key, key_size);


    sgx_status_t status = sign(sign_arr, enclave_signature, key_size);
    if (status != SGX_SUCCESS) {
        printf("Failed to sign the message: %d\n", status);

        return status;
    }

    return SGX_SUCCESS;
}

sgx_status_t decrypt_data(uint8_t* ciphertext, size_t ciphertext_size, uint8_t* tag) {
    sgx_aes_gcm_128bit_key_t aes_key;
    memcpy(aes_key, enclave_key, KEY_SIZE);

    uint8_t *iv = (uint8_t *) calloc(IV_SIZE, sizeof(uint8_t));

    sgx_status_t status = sgx_rijndael128GCM_decrypt(
        &aes_key, 
        ciphertext, 
        ciphertext_size, 
        ciphertext, 
        iv, 
        IV_SIZE, 
        NULL, 
        0, 
        (sgx_aes_gcm_128bit_tag_t*)tag
    );
    return status;
}


sgx_status_t encrypt_data(
    const sgx_key_128bit_t* key,
    uint8_t* plaintext,
    uint32_t plaintext_len,
    uint8_t* ciphertext,
    sgx_aes_gcm_128bit_tag_t* out_mac) {

    uint8_t *iv = (uint8_t *) calloc(IV_SIZE, sizeof(uint8_t));
    // TODO: Set 'iv' to a new, random value for each message

    sgx_status_t ret = sgx_rijndael128GCM_encrypt(
        key, 
        plaintext,
        plaintext_len,
        ciphertext,
        iv,
        IV_SIZE,
        NULL,
        0, 
        out_mac
    );

    free(iv);
    return ret;
}
