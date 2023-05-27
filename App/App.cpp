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
#include <dirent.h>
#include <ctype.h>

#define MATRIX_CARD_SIZE 64
#define ENCLAVE_FILE "Enclave.signed.so"
#define KEY_SIZE 16
#define TAG_SIZE 16

sgx_enclave_id_t global_eid = 0;
sgx_enclave_id_t global_eid1 = 0;
sgx_enclave_id_t global_eid2 = 0;

int encrypt_data(const char* plaintext, size_t plaintext_len, uint8_t* key, uint8_t* ciphertext, uint8_t* tag) {
    EVP_CIPHER_CTX *ctx;

    int len;
    int ciphertext_len = 0;

    if(!(ctx = EVP_CIPHER_CTX_new())) {
        printf("Failed to create new EVP_CIPHER_CTX");
    }

    uint8_t *iv = (uint8_t *) calloc(12, sizeof(uint8_t));

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, key, iv)) {
        printf("Failed to initialize encryption");
    }

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, (const unsigned char*) plaintext, plaintext_len)) {
        printf("Failed to update encryption");
    }

    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        printf("Failed to finalize encryption");
    }

    ciphertext_len += len;

    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) {
        printf("Failed to get authentication tag");
    }

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int is_number(const char *str) {
    while (*str != '\0') {
        if (!isdigit((unsigned char)* str)) {
            return 0; 
        }
        str++;
    }

    return 1;
}

char **get_file_names_for_enclave_version(uint8_t version, int *count) {
    char **file_names = NULL;
    *count = 0;

    DIR *dir = opendir("cards");
    if (dir == NULL) {
        printf("* unable to open directory 'cards' \n");
        return NULL;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (!is_number(entry->d_name)) {
            continue;
        }

        char file_name[256];
        snprintf(file_name, sizeof(file_name), "cards/%s", entry->d_name);
        FILE *file = fopen(file_name, "rb");

        if (file == NULL) {
            printf("* unable to open file: %s\n", file_name);
            continue;
        }

        fseek(file, -1, SEEK_END);
        unsigned char last_byte;
        fread(&last_byte, 1, 1, file);
        if (last_byte == version) {
            file_names = (char**) realloc(file_names, (*count + 1) * sizeof(char*));
            file_names[*count] = (char*) malloc(strlen(entry->d_name) + 1);
            strcpy(file_names[*count], entry->d_name);
            (*count)++;
        }

        fclose(file);
    }

    closedir(dir); 

    return file_names;
}

int main(int argc, char const *argv[]) {
    if (argc <= 1) {
        print_usage(argv);
        return 0;
    }

    int ret;
    sgx_status_t retval;

    if (strcmp(argv[1], "--card-versions") == 0) {
        if (argc != 3) {
            print_usage(argv);
            return 1;
        }

        uint32_t version;
        sscanf(argv[2], "%d", &version);

        int count; 
        char **file_names = get_file_names_for_enclave_version(version, &count);
        if (count == 0) {
            printf("[+] no cards found for version %d\n", version);
            return 0;
        }

        printf("[+] cards for version %d are:\n", version);
        for (int i = 0; i < count; i++) {
            printf("  - %s\n", file_names[i]);
        }
        printf("\n");
        return 0;
    }

    if (strcmp(argv[1], "--migrate") == 0) { 
        char const *source_enclave_so = argv[2];
        char const *dest_enclave_so = argv[3];

        sgx_status_t ret;
        sgx_status_t dh_status;
        sgx_dh_msg1_t msg1;
        sgx_dh_msg2_t msg2;
        sgx_dh_msg3_t msg3;

        printf("[+] migration requested between %s and %s\n", source_enclave_so, dest_enclave_so);

        printf("[+] initializing source enclave %s\n", source_enclave_so);
        if (initialize_enclave(&global_eid1, source_enclave_so) < 0) {
            printf("* failed to initialize enclave %s\n", source_enclave_so);
            return 1;
        }

        uint8_t source_enclave_version = 0;
        ret = ecall_get_enclave_version(global_eid1, &retval, &source_enclave_version);
        printf("\t[-] source enclave version: %d\n", source_enclave_version);

        int count; 
        char **file_names = get_file_names_for_enclave_version(source_enclave_version, &count);
        if (count == 0) {
            printf("* no files detected to migrate\n");
            return 1;
        }

        printf("[+] initializing destination enclave %s\n", dest_enclave_so);
        if (initialize_enclave(&global_eid2, dest_enclave_so) < 0) {
            printf("* failed to initialize enclave %s\n", dest_enclave_so);
            return 1;
        }

        uint8_t dest_enclave_version = 0;
        ret = ecall_get_enclave_version(global_eid2, &retval, &dest_enclave_version);
        printf("\t[-] destination enclave version: %d\n", dest_enclave_version);

        printf("\n[+] starting Diffie-Hellman key exchange...\n");

        if((ret = ecall_init_session_initiator(global_eid1, &dh_status)) != SGX_SUCCESS || dh_status != SGX_SUCCESS) {
          print_error_message((ret != SGX_SUCCESS) ? ret : dh_status, "ecall_init_session_initiator");
          return 1;
        }

        if((ret = ecall_init_session_responder(global_eid2, &dh_status)) != SGX_SUCCESS || dh_status != SGX_SUCCESS) {
          print_error_message((ret != SGX_SUCCESS) ? ret : dh_status, "ecall_init_session_responder");
          return 1;
        }

        if((ret = ecall_create_message1(global_eid2, &msg1, &dh_status)) != SGX_SUCCESS || dh_status != SGX_SUCCESS) {
          print_error_message((ret != SGX_SUCCESS) ? ret : dh_status, "ecall_create_message1");
          return 1;
        }

        if((ret = ecall_process_message1(global_eid1, &msg1, &msg2, &dh_status)) != SGX_SUCCESS || dh_status != SGX_SUCCESS) {
          print_error_message((ret != SGX_SUCCESS) ? ret : dh_status, "ecall_process_message1");
          return 1;
        }

        if((ret = ecall_process_message2(global_eid2, &msg2, &msg3, &dh_status)) != SGX_SUCCESS || dh_status != SGX_SUCCESS) {
          print_error_message((ret != SGX_SUCCESS) ? ret : dh_status, "ecall_process_message2");
          return 1;
        }

        if((ret = ecall_process_message3(global_eid1, &msg3, &dh_status)) != SGX_SUCCESS || dh_status != SGX_SUCCESS) {
          print_error_message((ret != SGX_SUCCESS) ? ret : dh_status, "ecall_process_message3");
          return 1;
        }

        printf("[+] Diffie-Hellman key exchange completed successfully\n\n");

        for (int i = 0; i < count; i++) {
            uint32_t client_id = atoi(file_names[i]);

            printf("[+] migrating card for client %d\n", client_id);

            uint8_t *encrypted = NULL;
            size_t size = 0;
            sgx_aes_gcm_128bit_tag_t *out_tag = NULL;
            ret = ecall_migration_prepare_record(global_eid1, &retval, client_id, &encrypted, &size, &out_tag);
            if (ret != SGX_SUCCESS) {
                print_error_message((ret != SGX_SUCCESS) ? ret : dh_status, "ecall_migration_prepare_record");
                return 1;
            }

            ret = ecall_migration_finalize(global_eid2, &retval, encrypted, size, (uint8_t*) out_tag, 16);
            if (ret != SGX_SUCCESS) {
                print_error_message((ret != SGX_SUCCESS) ? ret : dh_status, "ecall_migration_finalize");
                return 1;
            }
        }

        printf("\n[+] migration complete\n");

        return 0;
    }

    // checks if there's a force enclave binary to use
    const char *enclave_so = "enclave.signed.so";
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--binary") == 0) {
            if ((i == argc - 1) || argc < 3) {
                print_usage(argv);
                return 1;
            }

            enclave_so = argv[i + 1]; 
        }
    }

    printf("[+] initializing enclave from %s\n", enclave_so);
    if (initialize_enclave(&global_eid, enclave_so) < 0) {
        printf("* failed to initialize enclave\n");
        return 1;
    }

    printf("[+] enclave started\n");

    uint8_t key[KEY_SIZE];
    ecall_generate_key(global_eid, &retval, key, KEY_SIZE);
    if (retval != SGX_SUCCESS) {
        printf("* failed to generate key\n");
    }

    if (retval != SGX_SUCCESS) {
        printf("* failed to create key in enclave\n");
        return 1;
    }

    if (strcmp(argv[1], "--setup") == 0) {
        if (argc != 3) {
            print_usage(argv);
            return 0;
        }

        printf("\t[+] client card setup requested\n");

        // Generate random array
        uint8_t *array = (uint8_t *)malloc(MATRIX_CARD_SIZE * sizeof(uint8_t));
        uint32_t client_id;
        sscanf(argv[2], "%d", &client_id);
        sgx_status_t status = ecall_setup_card(global_eid, &ret, client_id, array, MATRIX_CARD_SIZE);
        if (status != SGX_SUCCESS) {
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

        printf("\t[-] validating coords:\n");
        for (int i = 0; i < num_records; i++) {
            printf("\t (x=%hhu, y=%hhu) = %hhu\n", i, coords_arr[i].x, coords_arr[i].y, coords_arr[i].val);
        }

        uint8_t result = 0;
        uint32_t client_id;
        sscanf(argv[2], "%d", &client_id);

        time_t timestamp = time(NULL);

        int ret = ecall_validate_coords(global_eid, &retval, client_id, coords_arr, num_records, &result, (uint64_t)timestamp);

        printf("\n[+] validation result %s\n", result == 1 ? "TRUE" : "FALSE");

        return 0;
    }

    if (strcmp(argv[1], "--logs") == 0) {
        if (argc < 3) {
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
