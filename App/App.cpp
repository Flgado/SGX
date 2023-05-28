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
#include <ctype.h>
#include <getopt.h>
#include "App.h"

ECDSA256PublicKey enclave_public_key;

sgx_enclave_id_t global_eid = 0;
sgx_enclave_id_t global_eid1 = 0;
sgx_enclave_id_t global_eid2 = 0;

int main(int argc, char *argv[]) {
    if (argc == 1) {
        print_usage(argv);
    }

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

    const char *enclave_so = "enclave.signed.so";
    while ((opt = getopt_long(argc, argv, "hs:m:c:l:v:b:", options, &idx)) != -1) {
        switch(opt) {
            case 'h': 
                print_usage(argv);
                break;
            case 'b':
                print_yellow("custom binary selected: %s (if the argument is not first, it won't take action)\n", optarg);
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
                    print_red("Missing argument for --validate <client_id> <coords>\n");
                    return 1;
                }
                handle_validation_opt(optarg, argv[optind], enclave_so);
                optind++;
                break;
            case 'm':
                if (optind + 1 > argc) {
                    print_red("Missing argument for --migrate <src> <dst>\n");
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
        printf("[-] no cards found for version %d\n", version);
        return;
    }

    printf("[+] cards for version %d are: [ ", version);
    for (int i = 0; i < count; i++) {
        if (i == count - 1) {
            printf("%s", file_names[i]);
        }
        else {
            printf("%s, ", file_names[i]);
        }
    }
    printf(" ]\n");
}

void handle_signature_validation(const char *label, ECDSA256Signature signature, uint8_t *data, size_t size) {
    print_yellow("validating signature %s...\n", label);
    int validation_result;

    uint8_t *sign_arr = (uint8_t *)malloc(size);
    memcpy(sign_arr, (uint8_t*)data, size);

    bool validation_with_errors = validate_signature(
        &validation_result, 
        sign_arr, 
        size, 
        signature
    );

    if (!validation_with_errors) {
        print_red("* error validating signature (validation with errors)%s...\n", label);
        exit(1);
    }

    if (validation_result != 1) {
        print_red("* error validating signature (signature invalid)%s...\n", label);
        exit(1);
    }

    print_yellow("%s signature pass!\n", label);
}

void handle_setup_card_opt(char* client_id, const char* enclave_so) {
    int ret;
    sgx_status_t retval;

    printf("[+] initializing enclave from %s\n", enclave_so);
    if (initialize_enclave(&global_eid, enclave_so) < 0) {
        printf("* failed to initialize enclave\n");
        return;
    }

    uint8_t enclave_version = 0;
    ret = ecall_get_enclave_version(global_eid, &retval, &enclave_version);
    printf("[+] enclave started (version %d)\n", enclave_version);

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
        print_red("failed to setup card\n");
        return;
    }

    size_t array_size = MATRIX_CARD_SIZE * sizeof(uint16_t);
    uint8_t *sign_arr = (uint8_t *)malloc(array_size);
    memcpy(sign_arr, (uint8_t*)array, array_size);
    const char *label = "matrix data";
    handle_signature_validation(label, enclave_signature, sign_arr, array_size);

    // Save the card in cleartext to a .txt file.
    // This would probably not be here in a realer environment, but for testing 
    // purposes it's useful
    FILE *fp;
    char file_name[20];
    sprintf(file_name, "cards/%s.txt", client_id);

    fp = fopen(file_name, "w");
    if (fp == NULL) {
        print_red("could not open file %s for writing\n", file_name);
        return;
    }

    printf("\n\t*** CLIENT CARD CREATED FOR ID %s ***\n", client_id);

    // This mess is here to print the card to the stdout in a pretty way,
    // it also stores it to a .txt file so end up with duplicate prints 
    // for different streams
    print_green("\t    0   1   2   3   4   5   6   7\n");
    fprintf(fp, "    0   1   2   3   4   5   6   7\n");

    for (int i = 0; i < 8; i++) {
        print_green("\t%c ", 'A' + i);
        fprintf(fp, "%c ", 'A' + i);
        for (int j = 0; j < 8; j++) {
            print_green(" %3d", array[i * 8 + j]);
            fprintf(fp, " %3d", array[i * 8 + j]);
        }
        printf("\n");
        fprintf(fp, "\n");
    }
    printf("\n");
    fclose(fp);
}

void handle_logs_opt(char* client_id_str, const char* enclave_so) {
    printf("[+] initializing enclave from %s\n", enclave_so);
    if (initialize_enclave(&global_eid, enclave_so) < 0) {
        printf("* failed to initialize enclave\n");
        return;
    }

    sgx_status_t retval = SGX_SUCCESS;
    int ret = 0;

    uint8_t enclave_version = 0;
    ret = ecall_get_enclave_version(global_eid, &retval, &enclave_version);
    printf("[+] enclave started (version %d)\n", enclave_version);

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

    // logs are printed via ocalls
    ecall_print_logs(global_eid, &retval, &client_param, sizeof(client_param));
}

// we convert our coords struct into a char* so we can easily encrypt it for dispatching
// to the enclave
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

void handle_validation_opt(char* client_id_str, char* coords, const char* enclave_so) {
    sgx_status_t retval = SGX_SUCCESS;
    printf("[+] initializing enclave from %s\n", enclave_so);
    if (initialize_enclave(&global_eid, enclave_so) < 0) {
        printf("* failed to initialize enclave\n");
        return;
    }

    uint8_t enclave_version = 0;
    ecall_get_enclave_version(global_eid, &retval, &enclave_version);
    printf("[+] enclave started (version %d)\n", enclave_version);

    uint8_t *shared_key = (uint8_t*) malloc(KEY_SIZE);
    init_comm_keys(shared_key);

    struct Coords *parsed_coords = NULL;
    int num_coords = parse_coords(coords, &parsed_coords);

    printf("[+] validating coords for client %s:\n", client_id_str);
    bool return_early = false;
    for (int i = 0; i < num_coords; i++) {
        bool coords_are_valid = true;

        printf("%d: (%hhu, %hhu, %hhu) = %hhu\n", i, parsed_coords[i].x, parsed_coords[i].y, parsed_coords[i].pos, parsed_coords[i].val);

        // value to check is a single digit, 0-9
        if (parsed_coords[i].val < 0 || parsed_coords[i].val > 9) {
            print_red("* %d: wrong coords format for value, __:_=val. val should be a digit from 0 to 9\n", i);
            coords_are_valid = false;
            return_early = true;
        }

        // coordinates have to be within bounds
        if (parsed_coords[i].x < 0 || parsed_coords[i].x >= 8 || parsed_coords[i].y < 0 || parsed_coords[i].y >= 8) {
            print_red("* %d: wrong coords format for value coordinates, yx:_=_. coordinates should of the format a-h0-7\n", i);
            coords_are_valid = false;
            return_early = true;
        }

        // all matrix values are 3 digits long, digit position has to be 1-3
        if (parsed_coords[i].pos < 1 || parsed_coords[i].pos > 3) {
            print_red("* %d: wrong coords format for digit position, __:pos=_. pos should be a digit from 1 to 3\n", i);
            coords_are_valid = false;
            return_early = true;
        }
    }

    if (return_early) {
        print_red("** invalid coordinates, ignoring validation request\n");
        free(shared_key);
        return;
    }

    size_t coords_param_size = sizeof(Coords) * num_coords;
    char *coords_arr = (char*) malloc(coords_param_size);
    coords_to_byte_arr(coords_arr, parsed_coords, num_coords);

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
        SIGNATURE_SIZE
    );

    const char *label = "challenge_validation_result";
    uint8_t validation_result[1] = { result };
    handle_signature_validation(label, enclave_signature, validation_result, 1);

    if (result == 1) {
        print_green("\n*** CHALLENGE PASSED! ***\n\n");
    }
    else {
        print_red("\n*** CHALLENGE FAILED! ***\n\n");
    }
}

void handle_migration_opt(const char *source_enclave_so, const char *dest_enclave_so) {
    sgx_status_t retval;
    sgx_status_t ret;
    sgx_status_t dh_status;
    sgx_dh_msg1_t msg1;
    sgx_dh_msg2_t msg2;
    sgx_dh_msg3_t msg3;

    printf("[+] migration requested from \033[0;33m%s\033[0;0m to \033[0;33m%s\033[0;0m\n", source_enclave_so, dest_enclave_so);

    printf("[+] initializing source enclave \033[0;33m%s\033[0;0m\n", source_enclave_so);
    if (initialize_enclave(&global_eid1, source_enclave_so) < 0) {
        print_red("* failed to initialize enclave %s\n", source_enclave_so);
        return;
    }

    uint8_t source_enclave_version = 0;
    ret = ecall_get_enclave_version(global_eid1, &retval, &source_enclave_version);
    printf("[+] source enclave started (version %d)\n", source_enclave_version);

    int count; 
    char **file_names = get_file_names_for_enclave_version(source_enclave_version, &count);
    if (count == 0) {
        printf("* no files detected to migrate\n");
        return;
    }

    printf("[+] initializing destination enclave \033[0;33m%s\033[0;0m\n", dest_enclave_so);
    if (initialize_enclave(&global_eid2, dest_enclave_so) < 0) {
        printf("* failed to initialize enclave %s\n", dest_enclave_so);
        return;
    }

    uint8_t dest_enclave_version = 0;
    ret = ecall_get_enclave_version(global_eid2, &retval, &dest_enclave_version);
    printf("[+] destination enclave started (version %d)\n", dest_enclave_version);

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

        print_yellow("[+] migrating card for client %d\n", client_id);

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

    print_green("\n[+] migration complete\n");
}

int encrypt_data(const char* plaintext, size_t plaintext_len, uint8_t* key, uint8_t* ciphertext, uint8_t* tag) {
    EVP_CIPHER_CTX *ctx;

    int len;
    int ciphertext_len = 0;

    if(!(ctx = EVP_CIPHER_CTX_new())) {
        print_red("* failed to create new EVP_CIPHER_CTX");
    }

    uint8_t *iv = (uint8_t *) calloc(12, sizeof(uint8_t));

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, key, iv)) {
        print_red("* failed to initialize encryption");
    }

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, (const unsigned char*) plaintext, plaintext_len)) {
        print_red("* failed to update encryption");
    }

    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        print_red("* failed to finalize encryption");
    }

    ciphertext_len += len;

    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) {
        print_red("* failed to get authentication tag");
    }

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

bool validate_signature(int* result, const unsigned char* data, uint32_t data_len, ECDSA256Signature enclave_signature) {
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
        print_red("* failed to create ECDSA public key\n");
        BN_free(x);
        BN_free(y);
        return false;
    }
    BN_free(x);
    BN_free(y);

    ecdsa_sig = ECDSA_SIG_new();
    if(!ecdsa_sig) {
        print_red("* failed to create ECDSA sig\n");
        EC_KEY_free(ec_key);
        return false;
    }

    BIGNUM* r = BN_lebin2bn(enclave_signature.r, ECDSA256_SIGNATURE_R_SIZE, NULL);
    if(!r) {
        print_red("* failed to create ECDSA signature r\n");
        ECDSA_SIG_free(ecdsa_sig);
        EC_KEY_free(ec_key);
        return false;
    }

    BIGNUM* s = BN_lebin2bn(enclave_signature.s, ECDSA256_SIGNATURE_S_SIZE, NULL);
    if(!s) {
        print_red("* failed to create ECDSA signature s\n");
        ECDSA_SIG_free(ecdsa_sig);
        EC_KEY_free(ec_key);
        return false;
    }

    if(ECDSA_SIG_set0(ecdsa_sig, r, s) == 0) {
        print_red("* failed at ECDSA_SIG_set0()\n");
        ECDSA_SIG_free(ecdsa_sig);
        EC_KEY_free(ec_key);
        return false;
    }

    uint8_t hash[SHA256_DIGEST_LENGTH];
    if(!SHA256(data, data_len, hash)) {
        print_red("* failed to compute SHA256\n");
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
        print_red("* failed to create ECDSA256 key pair. Error code: %d\n", retval);
        return;
    }

    struct ECDSA256Signature enclave_signature;
    ecall_generate_key(global_eid, &retval, key, KEY_SIZE, &enclave_signature, SIGNATURE_SIZE);
    if (retval != SGX_SUCCESS) {
        print_red("* failed to generate key\n");
        exit(1);
    }

    const char *label = "symmetric key";
    handle_signature_validation(label, enclave_signature, key, KEY_SIZE);
}