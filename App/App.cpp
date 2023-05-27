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
#include <getopt.h>

#define MATRIX_CARD_SIZE 64
#define KEY_SIZE 16
#define TAG_SIZE 16
#define ECDSA256_PUBLICKEY_GX_SIZE 32
#define ECDSA256_PUBLICKEY_GY_SIZE 32
#define ECDSA256_SIGNATURE_R_SIZE 32
#define ECDSA256_SIGNATURE_S_SIZE 32
#define ECDSA256

ECDSA256PublicKey enclave_public_key;

sgx_enclave_id_t global_eid = 0;
sgx_enclave_id_t global_eid1 = 0;
sgx_enclave_id_t global_eid2 = 0;

void handle_migration_opt(char *source_enclave_so, char *dest_enclave_so);
void handle_validation_opt(char* client_id_str, char* coords, char* enclave_so);
void handle_logs_opt(char* client_id_str, char* enclave_so);
void handle_setup_card_opt(uint32_t client_id, char* enclave_so);
void handle_card_versions_opt(uint32_t version);

static bool validate_signature(int* result, const unsigned char* data, uint32_t data_len, ECDSA256Signature enclave_signature)
{
    EC_KEY* ec_key;
    ECDSA_SIG* ecdsa_sig;

    // Creat an EC_KEY object and set the public key
    ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

    if(!ec_key)
    {
        fprintf(stderr, "Failed at EC_KEY_new_curve_name().\n");
        return false;
    }

    // Set the public key coordinates
    BIGNUM* x = BN_lebin2bn(enclave_public_key.gx, ECDSA256_PUBLICKEY_GX_SIZE, NULL);
    BIGNUM* y = BN_lebin2bn(enclave_public_key.gy, ECDSA256_PUBLICKEY_GY_SIZE, NULL);
    if(EC_KEY_set_public_key_affine_coordinates(ec_key, x, y) <=0)
    {
        fprintf(stderr, "Failed to create ECDSA publicKey.\n");
        BN_free(x);
        BN_free(y);
        return false;
    }
    BN_free(x);
    BN_free(y);

    // Create an ECDSA_SIG object and set the signature values
    ecdsa_sig = ECDSA_SIG_new();
    if(!ecdsa_sig)
    {
        fprintf(stderr, "Failed to create ECDSA sign.\n");
        EC_KEY_free(ec_key);
        return false;
    }

    // set the signature r value
    BIGNUM* r = BN_lebin2bn(enclave_signature.r, ECDSA256_SIGNATURE_R_SIZE, NULL);
    if(!r)
    {
        fprintf(stderr, "Failed to create signature r.\n");
        ECDSA_SIG_free(ecdsa_sig);
        EC_KEY_free(ec_key);
        return false;
    }

    BIGNUM* s = BN_lebin2bn(enclave_signature.s, ECDSA256_SIGNATURE_S_SIZE, NULL);
    if(!s)
    {
        fprintf(stderr, "Failed to create signature s.\n");
        ECDSA_SIG_free(ecdsa_sig);
        EC_KEY_free(ec_key);
        return false;
    }

    // Assign r and s values for signature
    if(ECDSA_SIG_set0(ecdsa_sig, r, s) == 0)
    {
        fprintf(stderr, "Failed at ECDSA_SIG_set0().\n");
        ECDSA_SIG_free(ecdsa_sig);
        EC_KEY_free(ec_key);
        return false;
    }

    // Compute the SHA256 hash of the message
    uint8_t hash[SHA256_DIGEST_LENGTH];
    if(!SHA256(data, data_len, hash))
    {
        fprintf(stderr, "Failed to compute SH256 hash.\n");
        ECDSA_SIG_free(ecdsa_sig);
        EC_KEY_free(ec_key);
        return false;
    }

    (*result) = ECDSA_do_verify(hash, SHA256_DIGEST_LENGTH, ecdsa_sig, ec_key);

    ECDSA_SIG_free(ecdsa_sig);
    EC_KEY_free(ec_key);

    return true;
}

int encrypt_data(const char* plaintext, size_t plaintext_len, uint8_t* key, uint8_t* ciphertext, uint8_t* tag);
int is_number(const char *str);

int main(int argc, char *argv[]) {
    int opt = 0;
    static struct option options[] = {
        {"help",          no_argument, 0, 'h'},
        {"setup",         required_argument, 0, 's'},
        {"migrate",       required_argument, 0, 'm'},
        {"card-versions", required_argument, 0, 'c'},
        {"logs",          required_argument, 0, 'l'},
        {"validate",      required_argument, 0, 'v'},
        {"binary",        required_argument, 0, 'b'},
    };

    int idx = 0;

    char *enclave_so = "enclave.signed.so";
    while ((opt = getopt_long(argc, argv, "hs:m:c:l:v:b:", options, &idx)) != -1) {
        switch(opt) {
            case 'h': 
                print_usage(argv);
                break;
            case 'b':
                printf("Custom binary selected: %s\n", optarg);
                enclave_so = optarg;
                break;
            case 'c':
                uint32_t version;
                sscanf(optarg, "%d", &version);
                handle_card_versions_opt(version);
                break;
            case 's':
                uint32_t client_id;
                sscanf(optarg, "%d", &client_id);
                handle_setup_card_opt(client_id, enclave_so);
                break;
            case 'l':
                handle_logs_opt(optarg, enclave_so);
                break;
            case 'v':
                if (optind + 1 > argc) {
                    printf("Missing argument for --validate <client_id> <coords>\n");
                    return 1;
                }
                handle_validation_opt(optarg, argv[optind], enclave_so);
                optind++;
                break;
            case 'm':
                if (optind + 1 > argc) {
                    printf("Missing argument for --migrate <src> <dst>\n");
                    return 1;
                }
                handle_migration_opt(optarg, argv[optind]);
                optind++;
                break;
            default: 
                print_usage(argv); 
                return 0;
        }
    }
    return 0;
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

void handle_card_versions_opt(uint32_t version) {
    int count; 
    char **file_names = get_file_names_for_enclave_version(version, &count);
    if (count == 0) {
        printf("[+] no cards found for version %d\n", version);
        return;
    }

    printf("[+] cards for version %d are:\n", version);
    for (int i = 0; i < count; i++) {
        printf("  - %s\n", file_names[i]);
    }
    printf("\n");
}

void handle_setup_card_opt(uint32_t client_id, char* enclave_so) {
    int ret;
    sgx_status_t retval;

    printf("[+] initializing enclave from %s\n", enclave_so);
    if (initialize_enclave(&global_eid, enclave_so) < 0) {
        printf("* failed to initialize enclave\n");
        return;
    }

    printf("[+] enclave started\n");

    ecall_generate_ecc_key_pair(global_eid, &retval, &enclave_public_key, ECDSA256_PUBLICKEY_GX_SIZE+ECDSA256_PUBLICKEY_GY_SIZE);
    if (retval != SGX_SUCCESS) {
        printf("Failed to create Ecdsa256 key pair. Error code: %d\n", retval);
        return;
    }

    uint8_t key[KEY_SIZE];
    ecall_generate_key(global_eid, &retval, key, KEY_SIZE);
    if (retval != SGX_SUCCESS) {
        printf("* failed to generate key\n");
    }

    if (retval != SGX_SUCCESS) {
        printf("* failed to create key in enclave\n");
        return;
    }

    printf("\t[+] client card setup requested\n");
    // ASSINAR
    // Generate random array
    uint8_t *array = (uint8_t *)malloc(MATRIX_CARD_SIZE * sizeof(uint8_t));

    struct ECDSA256Signature enclave_signature;

    sgx_status_t status = ecall_setup_card(global_eid, &ret, client_id, array, &enclave_signature, ECDSA256_SIGNATURE_R_SIZE+ECDSA256_SIGNATURE_S_SIZE, MATRIX_CARD_SIZE);
    if (status != SGX_SUCCESS) {
        return;
    }

    int validation_result;
    bool validatio_with_errors = validate_signature(&validation_result, array, MATRIX_CARD_SIZE * sizeof(uint8_t), enclave_signature);

    if (!validatio_with_errors) {
        printf("* Error in signature validation\n");
        exit(1);
    }
 
    if (validation_result != 1) {
        printf("* Signature invalide\n");
        exit(1);
    }

    pretty_print_arr(array, MATRIX_CARD_SIZE, 8);
}

void handle_logs_opt(char* client_id_str, char* enclave_so) {
    printf("[+] initializing enclave from %s\n", enclave_so);
    if (initialize_enclave(&global_eid, enclave_so) < 0) {
        printf("* failed to initialize enclave\n");
        return;
    }

    printf("[+] enclave started\n");
    sgx_status_t retval = SGX_SUCCESS;

    // client_id encryption
    size_t plaintext_len = strlen(client_id_str);
    uint8_t* ciphertext = (uint8_t*) malloc(plaintext_len);
    uint8_t* tag = (uint8_t*) malloc(TAG_SIZE);

    uint8_t key[KEY_SIZE];
    ecall_generate_key(global_eid, &retval, key, KEY_SIZE);
    if (retval != SGX_SUCCESS) {
        printf("* failed to generate key\n");
    }

    if (retval != SGX_SUCCESS) {
        printf("* failed to create key in enclave\n");
        return;
    }

    int len = encrypt_data(client_id_str, plaintext_len, key, ciphertext, tag);

    // call ecall_print_logs with encrypted client_id
    ecall_print_logs(global_eid, &retval, ciphertext, len, tag);
}

void handle_validation_opt(char* client_id_str, char* coords, char* enclave_so) {
    sgx_status_t retval = SGX_SUCCESS;
    printf("[+] initializing enclave from %s\n", enclave_so);
    if (initialize_enclave(&global_eid, enclave_so) < 0) {
        printf("* failed to initialize enclave\n");
        return;
    }

    ecall_generate_ecc_key_pair(global_eid, &retval, &enclave_public_key, ECDSA256_PUBLICKEY_GX_SIZE+ECDSA256_PUBLICKEY_GY_SIZE);
    if (retval != SGX_SUCCESS) {
        printf("Failed to create Ecdsa256 key pair. Error code: %d\n", retval);
        return;
    }

    struct Coords *coords_arr = NULL;
    int num_records = parse_coords(coords, &coords_arr);

    printf("\t[-] validating coords for client %s:\n", client_id_str);
    for (int i = 0; i < num_records; i++) {
        printf("\t (x=%hhu, y=%hhu) = %hhu\n", coords_arr[i].x, coords_arr[i].y, coords_arr[i].val);
    }

    uint8_t result = 0;
    uint32_t client_id;
    sscanf(client_id_str, "%d", &client_id);

    time_t timestamp = time(NULL);

    struct ECDSA256Signature enclave_signature;
    int ret = ecall_validate_coords(global_eid, &retval, client_id, coords_arr, num_records, &result, (uint64_t)timestamp, &enclave_signature, ECDSA256_SIGNATURE_S_SIZE+ECDSA256_SIGNATURE_R_SIZE);

    int validation_result;
    uint8_t result_validation[1] = { result };
    bool validatio_with_errors = validate_signature(&validation_result, result_validation, sizeof(result_validation), enclave_signature);

    if (!validatio_with_errors) {
        printf("* Error in signature validation\n");
        exit(1);
    }
 
    if (validation_result != 1) {
        printf("* Signature invalide\n");
        exit(1);
    }

    printf("\n[+] validation result %s\n", result == 1 ? "TRUE" : "FALSE");
}

void handle_migration_opt(char *source_enclave_so, char *dest_enclave_so) {
    sgx_status_t retval;
    sgx_status_t ret;
    sgx_status_t dh_status;
    sgx_dh_msg1_t msg1;
    sgx_dh_msg2_t msg2;
    sgx_dh_msg3_t msg3;

    printf("[+] migration requested between %s and %s\n", source_enclave_so, dest_enclave_so);

    printf("[+] initializing source enclave %s\n", source_enclave_so);
    if (initialize_enclave(&global_eid1, source_enclave_so) < 0) {
        printf("* failed to initialize enclave %s\n", source_enclave_so);
        return;
    }

    uint8_t source_enclave_version = 0;
    ret = ecall_get_enclave_version(global_eid1, &retval, &source_enclave_version);
    printf("\t[-] source enclave version: %d\n", source_enclave_version);

    int count; 
    char **file_names = get_file_names_for_enclave_version(source_enclave_version, &count);
    if (count == 0) {
        printf("* no files detected to migrate\n");
        return;
    }

    printf("[+] initializing destination enclave %s\n", dest_enclave_so);
    if (initialize_enclave(&global_eid2, dest_enclave_so) < 0) {
        printf("* failed to initialize enclave %s\n", dest_enclave_so);
        return;
    }

    uint8_t dest_enclave_version = 0;
    ret = ecall_get_enclave_version(global_eid2, &retval, &dest_enclave_version);
    printf("\t[-] destination enclave version: %d\n", dest_enclave_version);

    printf("\n[+] starting Diffie-Hellman key exchange...\n");

    if((ret = ecall_init_session_initiator(global_eid1, &dh_status)) != SGX_SUCCESS || dh_status != SGX_SUCCESS) {
      print_error_message((ret != SGX_SUCCESS) ? ret : dh_status, "ecall_init_session_initiator");
      return;
    }

    if((ret = ecall_init_session_responder(global_eid2, &dh_status)) != SGX_SUCCESS || dh_status != SGX_SUCCESS) {
      print_error_message((ret != SGX_SUCCESS) ? ret : dh_status, "ecall_init_session_responder");
      return;
    }

    if((ret = ecall_create_message1(global_eid2, &msg1, &dh_status)) != SGX_SUCCESS || dh_status != SGX_SUCCESS) {
      print_error_message((ret != SGX_SUCCESS) ? ret : dh_status, "ecall_create_message1");
      return;
    }

    if((ret = ecall_process_message1(global_eid1, &msg1, &msg2, &dh_status)) != SGX_SUCCESS || dh_status != SGX_SUCCESS) {
      print_error_message((ret != SGX_SUCCESS) ? ret : dh_status, "ecall_process_message1");
      return;
    }

    if((ret = ecall_process_message2(global_eid2, &msg2, &msg3, &dh_status)) != SGX_SUCCESS || dh_status != SGX_SUCCESS) {
      print_error_message((ret != SGX_SUCCESS) ? ret : dh_status, "ecall_process_message2");
      return; 
    }

    if((ret = ecall_process_message3(global_eid1, &msg3, &dh_status)) != SGX_SUCCESS || dh_status != SGX_SUCCESS) {
      print_error_message((ret != SGX_SUCCESS) ? ret : dh_status, "ecall_process_message3");
      return;
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
            return;
        }

        ret = ecall_migration_finalize(global_eid2, &retval, encrypted, size, (uint8_t*) out_tag, 16);
        if (ret != SGX_SUCCESS) {
            print_error_message((ret != SGX_SUCCESS) ? ret : dh_status, "ecall_migration_finalize");
            return;
        }
    }

    printf("\n[+] migration complete\n");
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