#ifndef _ENCLAVE_H
#define _ENCLAVE_H

#include "Enclave_t.h"
#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "sgx_dh.h"
#include "sign.h"

//#include "serializer.h"
//#include "encryption.h"

/*
 * Enclave's version. This variable should be updated in every version
 * of the enclave, in increments of 1
*/
#define ENCLAVE_VERSION 3

/*
 * Policy for the sealing key. If we use MRENCLAVE, subsequent versions
 * of the code will yield different keys, thus making it impossible 
 * to unseal existing cards
*/
#define KEY_POLICY SGX_KEYPOLICY_MRENCLAVE

/*
 * Gets the current version of the enclave, from `ENCLAVE_VERSION`
*/
sgx_status_t ecall_get_enclave_version(uint8_t *version); 

/*
 * Diffie-Hellman Key Exchange functions. An Enclave can be either an initiator
 * or a responder, we use this for the migration process, to agree on a common
 * key, so that we can safely transfer unsealed data between different versions
 * of the enclave, encrypted
*/
void ecall_init_session_initiator(sgx_status_t *dh_status); 
void ecall_init_session_responder(sgx_status_t *dh_status);
void ecall_create_message1(sgx_dh_msg1_t *msg1, sgx_status_t *dh_status);
void ecall_process_message1(const sgx_dh_msg1_t *msg1, sgx_dh_msg2_t *msg2, sgx_status_t *dh_status);
void ecall_process_message2(const sgx_dh_msg2_t *msg2, sgx_dh_msg3_t *msg3,sgx_status_t *dh_status);
void ecall_process_message3(const sgx_dh_msg3_t *msg3, sgx_status_t *dh_status);

/*
 * Unseal function, uses SGX unseal function under the hood
*/
sgx_status_t unseal(
    uint8_t* sealed_data_ptr, 
    size_t sealed_data_size, 
    uint8_t** plaintext_ptr, 
    size_t* plaintext_size_ptr, 
    uint8_t** aad_ptr, 
    size_t* aad_size_ptr
);

/*
 * Seal function, uses SGX unseal function under the hood. Policy set under KEY_POLICY
*/
sgx_status_t seal(
    uint8_t *plaintext, 
    size_t plaintext_len, 
    uint8_t *aad, 
    size_t aad_len, 
    uint8_t **sealed_data_ptr, 
    size_t *sealed_data_size_ptr
);

/*
 * Prepares record for migration. Essentially this function will encrypt an unsealed 
 * card and return it back into untrusted zone, allowing for it to be sent securely 
 * to the end-version enclave
*/
sgx_status_t ecall_migration_prepare_record(
    uint32_t client_id, 
    uint8_t **encrypted, 
    size_t *encrypted_sz, 
    sgx_aes_gcm_128bit_tag_t **out_mac
);

/*
 * Takes a prepared record (encrypted) and finalizes its migration, but sealing it
 * under the target version enclave
*/
sgx_status_t ecall_migration_finalize(uint8_t *encrypted, size_t encrypted_sz, uint8_t *mac, size_t mac_sz);

/*
 * Takes a card, seals it and stores it into the file system (via ocalls)
*/
int ecall_encrypt_card(Card *card);

/*
 * Sets up a new card, given a client identifier and outputs its array once to stdout
*/
int ecall_setup_card(EncryptedParam *client_param, size_t client_param_size, uint16_t *array, size_t array_size);

/*
 * Given an encrypted client_id, unseals its card and prints the access logs
*/
sgx_status_t ecall_print_logs(EncryptedParam *client_param, size_t client_param_size);

/*
 * Given a set of coordinates for a specific client, validates them against the 
 * matrix card 
*/
sgx_status_t ecall_validate_coords(
    EncryptedParam *client_param, 
    size_t client_param_size,
    EncryptedParam *coords_param, 
    size_t coords_param_size,
    uint8_t *result, 
    uint64_t timestamp
);

/*
 * Gets a card from the client id
*/
int get_card_from_client_id(uint32_t client_id, Card *card);

/*
 * Converts a string to uinsigned int
*/
uint32_t convert_string_to_uint32_t(uint8_t* str);

#endif
