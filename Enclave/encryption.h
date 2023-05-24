#ifndef ENCRYPTION_H_
#define ENCRYPTION_H_

#define KEY_SIZE 16
#define IV_SIZE 12

void printf(char *format, ...);
sgx_status_t ecall_generate_key(uint8_t* key, size_t key_size);
sgx_status_t decrypt_data(uint8_t* ciphertext, size_t ciphertext_size, uint8_t* tag);
sgx_status_t encrypt_data(
    const sgx_key_128bit_t* key,
    uint8_t* plaintext,
    uint32_t plaintext_len,
    uint8_t* ciphertext,
    sgx_aes_gcm_128bit_tag_t* out_mac
);

#endif