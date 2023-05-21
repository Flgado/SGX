#include <stdio.h>
#include <iostream>
#include <iomanip>
#include <string>
#include "Enclave_u.h"
#include "sgx_urts.h"
#include "sgx_trts.h"
#include "sgx_ukey_exchange.h"
#include "sgx_utils/sgx_utils.h"
#include "time.h"
#include "utils.h"
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define MATRIX_CARD_SIZE 64
#define ENCLAVE_FILE "Enclave.signed.so"
#define KEY_SIZE 16
#define TAG_SIZE 16

sgx_enclave_id_t global_eid = 0;

int encrypt_data(const char* plaintext, size_t plaintext_len, uint8_t* key, uint8_t* ciphertext, uint8_t* tag) {
    EVP_CIPHER_CTX *ctx;

    int len;
    int ciphertext_len = 0;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) printf("Failed to create new EVP_CIPHER_CTX");

    uint8_t *iv = (uint8_t *) calloc(12, sizeof(uint8_t));

    /* Initialise the encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, key, iv)) 
    printf("Failed to initialize encryption");

    /* Provide the message to be encrypted, and obtain the encrypted output. */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, (const unsigned char*) plaintext, plaintext_len)) 
        printf("Failed to update encryption");

    ciphertext_len = len;

    /* Finalise the encryption. */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) 
        printf("Failed to finalize encryption");

    ciphertext_len += len;

    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) 
        printf("Failed to get authentication tag");

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int main(int argc, char const *argv[])
{
    if (argc <= 1)
    {
        print_usage(argv);
        return 0;
    }

    int ret;
    sgx_status_t retval;

    printf("app: initializing enclave\n");
    if (initialize_enclave(&global_eid, "enclave.token", "enclave.signed.so") < 0)
    {
        printf("app: failed to initialize enclave\n");
        return 1;
    }

    printf("app: enclave started\n");

    uint8_t key[KEY_SIZE];
    ecall_generate_key(global_eid, &retval, key, KEY_SIZE);
    if (retval != SGX_SUCCESS) {
        printf("failed to generate key\n");
    }

    if (retval != SGX_SUCCESS)
    {
        printf("app: failed to create key in enclave\n");
        return 1;
    }

    if (strcmp(argv[1], "--setup") == 0)
    {
        if (argc != 3)
        {
            print_usage(argv);
            return 0;
        }

        printf("\tapp: client card setup requested\n");

        // Generate random array
        uint8_t *array = (uint8_t *)malloc(MATRIX_CARD_SIZE * sizeof(uint8_t));
        uint32_t client_id;
        sscanf(argv[2], "%d", &client_id);
        sgx_status_t status = ecall_setup_card(global_eid, &ret, client_id, array, MATRIX_CARD_SIZE);
        if (status != SGX_SUCCESS)
        {
            return 1;
        }

        pretty_print_arr(array, MATRIX_CARD_SIZE, 8);

        return 0;
    }

    if (strcmp(argv[1], "--validate") == 0) {
        if (argc != 4) {
            print_usage(argv);
            return 0;
        }

        struct Coords *coords_arr = NULL;
        int num_records = parse_coords(argv[3], &coords_arr);

        printf("\n");
        for (int i = 0; i < num_records; i++) {
            printf("coords to check %d: x=%hhu, y=%hhu, val=%hhu\n", i, coords_arr[i].x, coords_arr[i].y, coords_arr[i].val);
        }

        uint8_t result = 0;
        uint32_t client_id;
        sscanf(argv[2], "%d", &client_id);

        time_t timestamp = time(NULL);

        // coords encryption
        //size_t plaintext_len = num_records * sizeof(Coords);
        //uint8_t* ciphertext = (uint8_t*) malloc(plaintext_len);
        //uint8_t* tag = (uint8_t*) malloc(TAG_SIZE);
        //int len = encrypt_data(argv[2], plaintext_len, key, ciphertext, tag);

        int ret = ecall_validate_coords(global_eid, &retval, client_id, coords_arr, num_records, &result, (uint64_t)timestamp);

        printf("\n -- validation result %s\n", result == 1 ? "true" : "false");

        return 0;
    }

    if (strcmp(argv[1], "--logs") == 0) {
        if (argc != 3) {
            print_usage(argv);
            return 0;
        }

        uint32_t client_id;
        sscanf(argv[2], "%d", &client_id);
        sgx_status_t retval = SGX_SUCCESS;

        // client_id encryption
        size_t plaintext_len = strlen(argv[2]);
        uint8_t* ciphertext = (uint8_t*) malloc(plaintext_len);
        uint8_t* tag = (uint8_t*) malloc(TAG_SIZE);
        int len = encrypt_data(argv[2], plaintext_len, key, ciphertext, tag);

        // call ecall_print_logs with encrypted client_id
        ecall_print_logs(global_eid, &retval, ciphertext, len, tag);
    }

    return 0;
}