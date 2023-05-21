#ifndef ENCRYPTION_H_
#define ENCRYPTION_H_

#define KEY_SIZE 16
#define IV_SIZE 12

sgx_status_t ecall_generate_key(uint8_t* key, size_t key_size);
sgx_status_t decrypt_data(uint8_t* ciphertext, size_t ciphertext_size, uint8_t* tag);

#endif