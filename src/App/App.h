#ifndef APP_H_
#define APP_H_

#include <openssl/ec.h>
#include "Enclave_u.h"

#define MATRIX_CARD_SIZE 64
#define KEY_SIZE 16
#define TAG_SIZE 16
#define ECDSA256_PUBLICKEY_GX_SIZE 32
#define ECDSA256_PUBLICKEY_GY_SIZE 32
#define ECDSA256_SIGNATURE_R_SIZE 32
#define ECDSA256_SIGNATURE_S_SIZE 32
#define SIGNATURE_SIZE ECDSA256_PUBLICKEY_GX_SIZE + ECDSA256_PUBLICKEY_GY_SIZE
#define ENCLAVE_PUBLIC_KEY_FILE "keys/pub"

bool validate_signature(int* result, const unsigned char* data, uint32_t data_len, ECDSA256Signature enclave_signature);
void handle_migration_opt(const char *source_enclave_so, const char *dest_enclave_so);
void handle_validation_opt(char* client_id_str, char* coords, const char* enclave_so);
void handle_logs_opt(char* client_id_str, const char* enclave_so);
void handle_setup_card_opt(char *client_id, const char* enclave_so);
void handle_card_versions_opt(uint32_t version);
void init_comm_keys(uint8_t *key);
int save_enclave_public_key_into_file();
int enclave_public_key_is_saved();
int read_enclave_public_key();

int encrypt_data(const char* plaintext, size_t plaintext_len, uint8_t* key, uint8_t* ciphertext, uint8_t* tag);

#endif