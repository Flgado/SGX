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
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#define MATRIX_CARD_SIZE 64
#define KEY_SIZE 16
#define TAG_SIZE 16
#define ECDSA256_PUBLICKEY_GX_SIZE 32
#define ECDSA256_PUBLICKEY_GY_SIZE 32
#define ECDSA256_SIGNATURE_R_SIZE 32
#define ECDSA256_SIGNATURE_S_SIZE 32
#define SIGNATURE_SIZE ECDSA256_PUBLICKEY_GX_SIZE + ECDSA256_PUBLICKEY_GY_SIZE
#define ENCLAVE_PUBLIC_KEY_FILE "keys/pub"

ECDSA256PublicKey enclave_public_key;

sgx_enclave_id_t global_eid = 0;
sgx_enclave_id_t global_eid1 = 0;
sgx_enclave_id_t global_eid2 = 0;

static bool validate_signature(int* result, const unsigned char* data, uint32_t data_len, ECDSA256Signature enclave_signature);
void handle_migration_opt(char *source_enclave_so, char *dest_enclave_so);
void handle_validation_opt(char* client_id_str, char* coords, char* enclave_so);
void handle_logs_opt(char* client_id_str, char* enclave_so);
void handle_setup_card_opt(char *client_id, char* enclave_so);
void handle_card_versions_opt(uint32_t version);
void init_comm_keys(uint8_t *key);
int save_enclave_public_key_into_file();
int enclave_public_key_is_save();
int read_enclave_public_key();

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
                handle_setup_card_opt(optarg, enclave_so);
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


int enclave_public_key_is_save() {
     struct stat st = {0};
    return stat(ENCLAVE_PUBLIC_KEY_FILE, &st);
}

int read_enclave_public_key()
{
    FILE* file = fopen(ENCLAVE_PUBLIC_KEY_FILE, "rb");
    if (file == NULL) {
        printf("Error opening the file.\n");
        return 1;
    }
    
    // Read the gx and gy arrays from the file
    fread(enclave_public_key.gx, sizeof(uint8_t), ECDSA256_PUBLICKEY_GX_SIZE, file);
    fread(enclave_public_key.gy, sizeof(uint8_t), ECDSA256_PUBLICKEY_GY_SIZE, file);
    
    // Close the file
    fclose(file);

    return 0;
}

int save_enclave_public_key_into_file()
{
    struct stat st = {0};
    if (stat("keys", &st) == -1) {
        mkdir("keys", 0700);
    }
    // Open the file for writing
    FILE* file = fopen(ENCLAVE_PUBLIC_KEY_FILE, "wb");
    if (file == NULL) {
        printf("Error opening the file.\n");
        return 1;
    }
    
    // Write the gx and gy arrays to the file
    fwrite(enclave_public_key.gx, sizeof(uint8_t), ECDSA256_PUBLICKEY_GX_SIZE, file);
    fwrite(enclave_public_key.gy, sizeof(uint8_t), ECDSA256_PUBLICKEY_GY_SIZE, file);
    
    // Close the file
    fclose(file);
    
    printf("Public key saved successfully.\n");
    
    return 0;
}

int get_enclave_public_key()
{
    sgx_status_t retval;
    if(enclave_public_key_is_save() != -1)
    {
        ecall_load_existing_private_key(global_eid, &retval);
        return read_enclave_public_key();
    }

    ecall_generate_ecc_key_pair(global_eid, &retval, &enclave_public_key, SIGNATURE_SIZE);
     if (retval != SGX_SUCCESS) {
        printf("Failed to create Ecdsa256 key pair. Error code: %d\n", retval);
        return 1;
    }

    return save_enclave_public_key_into_file();
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

void handle_signature_validation(char *label, ECDSA256Signature signature, uint8_t *data, size_t size) {
    int validation_result;

    uint8_t *sign_arr = (uint8_t *)malloc(size);
    memcpy(sign_arr, (uint8_t*)data, size);

    bool validatio_with_errors = validate_signature(
        &validation_result, 
        sign_arr, 
        size, 
        signature
    );

    if (!validatio_with_errors) {
        printf("* Error in signature validation\n");
        exit(1);
    }

    if (validation_result != 1) {
        printf("* Signature invalid\n");
        exit(1);
    }

    printf("\033[0;32m:: %s signature pass!\n\033[0m", label);
}

void handle_setup_card_opt(char* client_id, char* enclave_so) {
    int ret;
    sgx_status_t retval;

    printf("[+] initializing enclave from %s\n", enclave_so);
    if (initialize_enclave(&global_eid, enclave_so) < 0) {
        printf("* failed to initialize enclave\n");
        return;
    }

    printf("[+] enclave started\n");

    // client_id encryption
    size_t plaintext_len = strlen(client_id);
    uint8_t *ciphertext = (uint8_t*) malloc(plaintext_len);
    uint8_t *tag = (uint8_t*) malloc(TAG_SIZE);

    uint8_t *shared_key = (uint8_t*) malloc(KEY_SIZE);
    init_comm_keys(shared_key);

    int len = encrypt_data(client_id, plaintext_len, shared_key, ciphertext, tag);

    free(shared_key);

    struct EncryptedParam client_param;
    client_param.ciphertext = ciphertext;
    client_param.cipher_size = len;

    client_param.tag = tag;
    client_param.tag_size = TAG_SIZE;

    printf("\t[+] client card setup requested\n");

    // Generate random array
    uint16_t *array = (uint16_t *)malloc(MATRIX_CARD_SIZE * sizeof(uint16_t));
    struct ECDSA256Signature enclave_signature;
    sgx_status_t status = ecall_setup_card(
        global_eid, 
        &ret, 
        &client_param,
        sizeof(client_param),
        array, 
        &enclave_signature, 
        ECDSA256_SIGNATURE_R_SIZE + ECDSA256_SIGNATURE_S_SIZE, 
        MATRIX_CARD_SIZE  * sizeof(uint16_t)
    );
    if (status != SGX_SUCCESS) {
        printf("Failed to setup card\n");
        return;
    }

    size_t array_size = MATRIX_CARD_SIZE * sizeof(uint16_t);
    uint8_t *sign_arr = (uint8_t *)malloc(array_size);
    memcpy(sign_arr, (uint8_t*)array, array_size);
    handle_signature_validation("matrix data", enclave_signature, sign_arr, array_size);

    FILE *fp;
    char file_name[20];
    sprintf(file_name, "cards/%s.txt", client_id);

    fp = fopen(file_name, "w");
    if (fp == NULL) {
        printf("Could not open file %s for writing\n", file_name);
        return;
    }

    fprintf(fp, "    0   1   2   3   4   5   6   7\n");
    printf("\n\t    0   1   2   3   4   5   6   7\n");

    for (int i = 0; i < 8; i++) {
        printf("\t%c ", 'A' + i);
        fprintf(fp, "%c ", 'A' + i);
        for (int j = 0; j < 8; j++) {
            printf(" %3d", array[i * 8 + j]);
            fprintf(fp, " %3d", array[i * 8 + j]);
        }
        printf("\n");
        fprintf(fp, "\n");
    }
    printf("\n");
    fclose(fp);
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
    uint8_t *ciphertext = (uint8_t*) malloc(plaintext_len);
    uint8_t *tag = (uint8_t*) malloc(TAG_SIZE);

    uint8_t *shared_key = (uint8_t*) malloc(KEY_SIZE);
    init_comm_keys(shared_key);

    int len = encrypt_data(client_id_str, plaintext_len, shared_key, ciphertext, tag);

    free(shared_key);

    struct EncryptedParam client_param;
    client_param.ciphertext = ciphertext;
    client_param.cipher_size = len;

    client_param.tag = tag;
    client_param.tag_size = TAG_SIZE;

    // call ecall_print_logs with encrypted client_id
    ecall_print_logs(global_eid, &retval, &client_param, sizeof(client_param));
}

void coords_to_byte_arr(char *result, Coords *coords_arr, size_t num_records) {
    for (int i = 0; i < num_records; i++) {
        result[i * 4] = coords_arr[i].x;
        result[i * 4 + 1] = coords_arr[i].y;
        result[i * 4 + 2] = coords_arr[i].pos;
        result[i * 4 + 3] = coords_arr[i].val;
    }
}

EncryptedParam get_encrypted_param(char *plaintext, size_t plaintext_len, uint8_t* key) {
    EncryptedParam encrypted_param;

    uint8_t *ciphertext = (uint8_t*) malloc(plaintext_len);
    uint8_t *tag = (uint8_t*) malloc(TAG_SIZE);

    int len = encrypt_data(plaintext, plaintext_len, key, ciphertext, tag);

    encrypted_param.ciphertext = ciphertext;
    encrypted_param.cipher_size = len;

    encrypted_param.tag = tag;
    encrypted_param.tag_size = TAG_SIZE;

    return encrypted_param;
}

void handle_validation_opt(char* client_id_str, char* coords, char* enclave_so) {
    sgx_status_t retval = SGX_SUCCESS;
    printf("[+] initializing enclave from %s\n", enclave_so);
    if (initialize_enclave(&global_eid, enclave_so) < 0) {
        printf("* failed to initialize enclave\n");
        return;
    }

    int enclave_public_key_generated = get_enclave_public_key();
    if (enclave_public_key_generated != 0) {
        printf("Failed to create Ecdsa256 key pair. Error code: %d\n", retval);
        return;
    }

    struct Coords *coords_list = NULL;
    int num_records = parse_coords(coords, &coords_list);

    printf("\tvalidating coords for client %s:\n", client_id_str);
    for (int i = 0; i < num_records; i++) {
        printf("\t- (%hhu, %hhu, %hhu) = %hhu\n", coords_list[i].x, coords_list[i].y, coords_list[i].pos, coords_list[i].val);
    }

    uint8_t *shared_key = (uint8_t*) malloc(KEY_SIZE);
    init_comm_keys(shared_key);

    size_t coords_param_size = sizeof(Coords) * num_records;
    char *coords_arr = (char*) malloc(coords_param_size);
    coords_to_byte_arr(coords_arr, coords_list, num_records);

    EncryptedParam coords_param = get_encrypted_param(coords_arr, coords_param_size, shared_key);
    EncryptedParam client_param = get_encrypted_param(client_id_str, strlen(client_id_str), shared_key);

    free(shared_key);

    time_t timestamp = time(NULL);

    struct ECDSA256Signature enclave_signature;
    uint8_t result = 0;
    int ret = ecall_validate_coords(
        global_eid, 
        &retval, 
        &client_param,
        sizeof(client_param),
        &coords_param, 
        sizeof(coords_param),
        &result,
        (uint64_t)timestamp,
        &enclave_signature, 
        ECDSA256_SIGNATURE_S_SIZE + ECDSA256_SIGNATURE_R_SIZE
    );

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
        sgx_aes_gcm_128bit_tag_t *out_tag = (sgx_aes_gcm_128bit_tag_t*) malloc(sizeof(sgx_aes_gcm_128bit_tag_t));
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

static bool validate_signature(int* result, const unsigned char* data, uint32_t data_len, ECDSA256Signature enclave_signature) {
    EC_KEY* ec_key;
    ECDSA_SIG* ecdsa_sig;

    ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

    if(!ec_key) {
        fprintf(stderr, "Failed at EC_KEY_new_curve_name().\n");
        return false;
    }

    BIGNUM* x = BN_lebin2bn(enclave_public_key.gx, ECDSA256_PUBLICKEY_GX_SIZE, NULL);
    BIGNUM* y = BN_lebin2bn(enclave_public_key.gy, ECDSA256_PUBLICKEY_GY_SIZE, NULL);
    if(EC_KEY_set_public_key_affine_coordinates(ec_key, x, y) <=0) {
        fprintf(stderr, "Failed to create ECDSA publicKey.\n");
        BN_free(x);
        BN_free(y);
        return false;
    }
    BN_free(x);
    BN_free(y);

    ecdsa_sig = ECDSA_SIG_new();
    if(!ecdsa_sig) {
        fprintf(stderr, "Failed to create ECDSA sign.\n");
        EC_KEY_free(ec_key);
        return false;
    }

    BIGNUM* r = BN_lebin2bn(enclave_signature.r, ECDSA256_SIGNATURE_R_SIZE, NULL);
    if(!r) {
        fprintf(stderr, "Failed to create signature r.\n");
        ECDSA_SIG_free(ecdsa_sig);
        EC_KEY_free(ec_key);
        return false;
    }

    BIGNUM* s = BN_lebin2bn(enclave_signature.s, ECDSA256_SIGNATURE_S_SIZE, NULL);
    if(!s) {
        fprintf(stderr, "Failed to create signature s.\n");
        ECDSA_SIG_free(ecdsa_sig);
        EC_KEY_free(ec_key);
        return false;
    }

    if(ECDSA_SIG_set0(ecdsa_sig, r, s) == 0) {
        fprintf(stderr, "Failed at ECDSA_SIG_set0().\n");
        ECDSA_SIG_free(ecdsa_sig);
        EC_KEY_free(ec_key);
        return false;
    }

    uint8_t hash[SHA256_DIGEST_LENGTH];
    if(!SHA256(data, data_len, hash)) {
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

void init_comm_keys(uint8_t *key) {
    sgx_status_t retval;

    int enclave_public_key_generated = get_enclave_public_key();
    if (enclave_public_key_generated != 0) {
        printf("Failed to create Ecdsa256 key pair. Error code: %d\n", retval);
        return;
    }

    struct ECDSA256Signature enclave_signature;
    ecall_generate_key(global_eid, &retval, key, KEY_SIZE, &enclave_signature, SIGNATURE_SIZE);
    if (retval != SGX_SUCCESS) {
        printf("* failed to generate key\n");
        exit(1);
    }

    handle_signature_validation("symmetric key", enclave_signature, key, KEY_SIZE);
}