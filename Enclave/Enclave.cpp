#include "Enclave_t.h"
#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "sgx_dh.h"
#include "headers/serializer.h"
#include "headers/encryption.h"
#include "headers/utils.h"
#include "headers/Enclave.h"

sgx_dh_session_t dh_session;
sgx_key_128bit_t dh_key;
sgx_dh_session_enclave_identity_t dh_identity;

sgx_status_t ecall_get_enclave_version(uint8_t *version) {
    *version = ENCLAVE_VERSION;
    return SGX_SUCCESS;
}

sgx_status_t seal(
    uint8_t *plaintext, 
    size_t plaintext_len, 
    uint8_t *aad, 
    size_t aad_len, 
    uint8_t **sealed_data_ptr, 
    size_t *sealed_data_size_ptr) {

    if (!plaintext || !aad || !sealed_data_ptr || !sealed_data_size_ptr) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    sgx_status_t status;

    uint32_t sealed_data_size = sgx_calc_sealed_data_size((uint32_t)aad_len, (uint32_t)plaintext_len);
    if(sealed_data_size == UINT32_MAX) {
        return SGX_ERROR_UNEXPECTED;
    }

    sgx_sealed_data_t* sealed_data = (sgx_sealed_data_t*)malloc(sealed_data_size);
    if(sealed_data == NULL) {
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    // defaults
    sgx_attributes_t attributes;
    attributes.xfrm = SGX_XFRM_RESERVED;
    attributes.flags = 0xFF0000000000000B;

    status = sgx_seal_data_ex(
        KEY_POLICY,
        attributes,
        0,
        (uint32_t) aad_len, 
        aad, 
        (uint32_t) plaintext_len, 
        plaintext, 
        sealed_data_size, 
        sealed_data
    );

    if(SGX_SUCCESS != status) {
        free(sealed_data);
        return status;
    }

    *sealed_data_ptr = (uint8_t*) sealed_data;
    *sealed_data_size_ptr = sealed_data_size;
    return SGX_SUCCESS;
}

sgx_status_t unseal(
    uint8_t* sealed_data_ptr, 
    size_t sealed_data_size, 
    uint8_t** plaintext_ptr, 
    size_t* plaintext_size_ptr, 
    uint8_t** aad_ptr, 
    size_t* aad_size_ptr) {

    if (!sealed_data_ptr || !plaintext_ptr || !plaintext_size_ptr || !aad_ptr || !aad_size_ptr) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    sgx_status_t status;

    sgx_sealed_data_t* sealed_data = (sgx_sealed_data_t*)sealed_data_ptr;

    uint32_t aad_size = sgx_get_add_mac_txt_len(sealed_data);
    uint32_t plaintext_size = sgx_get_encrypt_txt_len(sealed_data);

    uint8_t* aad = (uint8_t*)malloc(aad_size);
    if(aad == NULL) {
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    uint8_t* plaintext = (uint8_t*)malloc(plaintext_size);
    if(plaintext == NULL) {
        free(aad);
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    status = sgx_unseal_data(sealed_data, aad, &aad_size, plaintext, &plaintext_size);
    if(SGX_SUCCESS != status) {
        free(aad);
        free(plaintext);
        return status;
    }

    *aad_ptr = aad;
    *aad_size_ptr = aad_size;
    *plaintext_ptr = plaintext;
    *plaintext_size_ptr = plaintext_size;
    return SGX_SUCCESS;
}

int get_card_from_client_id(uint32_t client_id, Card *card) {
    if (!card) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    sgx_status_t retval = SGX_SUCCESS;
    sgx_status_t ocall_status = SGX_SUCCESS;
    int ocall_return = 0;

    size_t sealed_data_size = 0;
    ocall_status = ocall_get_sealed_data_size(&ocall_return, (int)(client_id), &sealed_data_size);
    if (ocall_status != SGX_SUCCESS || ocall_return != 0) {
        return SGX_ERROR_UNEXPECTED;
    }

    uint8_t *sealed_data = (uint8_t*) malloc(sealed_data_size);
    if (sealed_data == NULL) {
        printf("error allocating memory for sealed data in get_card_from_client_id()\n");
        return SGX_ERROR_UNEXPECTED;
    }

    ocall_status = ocall_read_sealed_data(&ocall_return, (int) client_id, sealed_data, sealed_data_size);
    if (ocall_status != SGX_SUCCESS || ocall_return != 0) {
        printf("error calling ocall_read_sealed_data(): %d\n", ocall_status);
        free(sealed_data);
        return SGX_ERROR_UNEXPECTED;
    }

    uint8_t card_enclave_version = sealed_data[sealed_data_size - 1]; 
    printf("enclave: version %d\n", card_enclave_version);
    if (card_enclave_version != ENCLAVE_VERSION) {
        printf("** card was sealed with a different enclave version (please run a migration)**\n");
        free(sealed_data);
        return SGX_ERROR_UNEXPECTED;
    }

    uint8_t *unsealed = NULL;
    size_t unsealed_size = 0;
    uint8_t *aad = NULL;
    size_t aad_size = 0;

    retval = unseal(sealed_data, sealed_data_size, &unsealed, &unsealed_size, &aad, &aad_size);
    if (retval != SGX_SUCCESS) {
        printf("error unsealing data: %d\n", retval);
        free(sealed_data);
        return retval;
    }

    if (aad_size < sizeof(uint32_t)) {
        free(sealed_data);
        free(unsealed);
        free(aad);
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (client_id != *(uint32_t*) aad) {
        printf("failed aad verification\n");
        free(sealed_data);
        free(unsealed);
        free(aad);
        return retval;
    }

    *card = deserialize(std::vector<uint8_t>(unsealed, unsealed + unsealed_size));

    free(sealed_data);
    free(unsealed);
    free(aad);

    return SGX_SUCCESS;
}

int ecall_encrypt_card(Card *card) { 
    if (!card) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    std::vector<uint8_t> serialized = serialize(*card);

    uint8_t *sealed_data = NULL;
    size_t sealed_data_size = 0;

    sgx_status_t status = seal(
        serialized.data(), 
        serialized.size(), 
        (uint8_t*)&card->client_id, 
        sizeof(card->client_id), 
        &sealed_data, 
        &sealed_data_size
    );

    if (status != SGX_SUCCESS) {
        printf("seal failed: %d\n", status);
        return status;
    }

    // writes result into file, with the enclave version appended
    int ocall_return;
    uint8_t *sealed_with_version = (uint8_t *)malloc((sealed_data_size + 1) * sizeof(uint8_t));
    if (sealed_with_version == NULL) {
        printf("Error allocating memory for sealed_with_version.\n");
        free(sealed_data);
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    memcpy(sealed_with_version, sealed_data, sealed_data_size);
    sealed_with_version[sealed_data_size] = ENCLAVE_VERSION;

    ocall_write_sealed_data(&ocall_return, card->client_id, sealed_with_version, sealed_data_size + 1);
    if (ocall_return != 0) {
        free(sealed_data);
        free(sealed_with_version);
        return SGX_ERROR_UNEXPECTED;
    }

    free(sealed_data);
    free(sealed_with_version);

    return SGX_SUCCESS;
}

int ecall_setup_card(
    EncryptedParam *client_param, 
    size_t client_param_size,
    uint16_t *array, 
    ECDSA256Signature* enclave_signature, 
    size_t signature_size, 
    size_t array_size) {

    if (!client_param || !array || !enclave_signature) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    sgx_status_t decryption_result = decrypt_data(client_param->ciphertext, client_param->cipher_size, client_param->tag);
    if (decryption_result != SGX_SUCCESS) {
        printf("failed to decrypt\n");
        return decryption_result;
    }

    uint32_t client_id = convert_string_to_uint32_t(client_param->ciphertext);

    sgx_status_t status;
    Card card;
    card.client_id = client_id;

    for (int i = 0; i < 64; i++) {
        uint8_t value[2];
        status = sgx_read_rand(value, sizeof(value));
        if (status != SGX_SUCCESS) {
            ocall_print("error generating random number\n");
            return status;
        }
        
        uint16_t composed = ((uint16_t) value[0] << 8 | value[1]) % 900;
        composed += 100;
        array[i] = composed;
        card.matrix_data[i] = composed;
    }

    uint8_t *sign_arr = (uint8_t *)malloc(array_size);
    if (!sign_arr) {
        printf("Error: failed to allocate memory for sign_arr.\n");
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    memcpy(sign_arr, (uint8_t*)array, array_size);
    status = sign(sign_arr, enclave_signature, array_size);
    if (status != SGX_SUCCESS) {
        printf("Failed to sign the message: %d\n", status);
        free(sign_arr);
        return status;
    }

    int ret = ecall_encrypt_card(&card);
    if (ret != 0) {
        free(sign_arr);
        return SGX_ERROR_UNEXPECTED;
    }

    free(sign_arr);
    return SGX_SUCCESS; 
}

sgx_status_t ecall_print_logs(EncryptedParam *client_param, size_t client_param_size) {
    if (!client_param) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    sgx_status_t decryption_result = decrypt_data(client_param->ciphertext, client_param->cipher_size, client_param->tag);
    if (decryption_result != SGX_SUCCESS) {
        printf("failed to decrypt\n");
        return decryption_result;
    }

    uint32_t client_id = convert_string_to_uint32_t(client_param->ciphertext);

    Card card;
    int card_fetch_result = get_card_from_client_id(client_id, &card);
    if (card_fetch_result != 0) {
        return SGX_ERROR_UNEXPECTED;
    }

    if (!card.log.empty()) {
        for (const auto &entry : card.log) {
            uint64_t ts = (uint64_t) entry.first;
            bool validation_result = (bool) entry.second;

            char buffer[1000];
            snprintf(buffer, sizeof(buffer), "timestamp: %lu, validation result: %d\n", ts, validation_result);
            ocall_print(buffer);
        }
    }

    return SGX_SUCCESS;
}

bool coords_are_valid(Coords coords) {
    // value to check is a single digit, 0-9
    if (coords.val < 0 || coords.val > 9) {
        return false;
    }

    // coordinates have to be within bounds
    if (coords.x < 0 || coords.x >= 8 || coords.y < 0 || coords.y >= 8) {
        return false;
    }

    // all matrix values are 3 digits long, digit position has to be 1-3
    if (coords.pos < 1 || coords.pos > 3) {
        return false;
    }

    return true;
}

uint8_t extract_digit_from_target(uint16_t value, uint8_t position) {
    if (position == 1) return value / 100;
    if (position == 2) return (value / 10) % 10;
    if (position == 3) return value % 10;
    return value;
}

sgx_status_t ecall_validate_coords(
    EncryptedParam *client_param, 
    size_t client_param_size,
    EncryptedParam *coords_param, 
    size_t coords_param_size,
    uint8_t *result, 
    uint64_t timestamp,
    ECDSA256Signature *enclave_signature,
    size_t signature_size) {

    if (!coords_param || !result || !enclave_signature) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    sgx_status_t status;

    status = decrypt_data(client_param->ciphertext, client_param->cipher_size, client_param->tag);
    if (status != SGX_SUCCESS) {
        printf("failed to decrypt\n");
        return status;
    }

    uint32_t client_id = convert_string_to_uint32_t(client_param->ciphertext);
    
    Card card;
    int card_fetch_result = get_card_from_client_id(client_id, &card);
    if (card_fetch_result != SGX_SUCCESS) {
        printf("Failed to fetch card with client id: %u\n", client_id);
        return SGX_ERROR_UNEXPECTED;
    }

    if (!card.log.empty() && timestamp <= card.log.back().first) {
        printf("TIMESTAMP VALIDATION FAILED!\n");
        return SGX_ERROR_UNEXPECTED;
    }

    status = decrypt_data(coords_param->ciphertext, coords_param->cipher_size, coords_param->tag);
    if (status != SGX_SUCCESS) {
        printf("failed to decrypt%d\n");
        return status;
    }

    struct Coords *coords = (Coords*) coords_param->ciphertext;
    size_t num_coords = coords_param->cipher_size / 4;

    *result = 1;
    for (size_t i = 0; i < num_coords; i++) {
        if(!coords_are_valid(coords[i])) {
            return SGX_ERROR_INVALID_PARAMETER;
        }

        int matrix_index = coords[i].y * 8 + coords[i].x;
        int target_check_value = extract_digit_from_target(card.matrix_data[matrix_index], coords[i].pos);

        if (target_check_value != coords[i].val) {
            *result = 0;
        }
    }

    card.log.push_back({timestamp, *result});
    int ret = ecall_encrypt_card(&card);
    if (ret != 0) {
        return SGX_ERROR_UNEXPECTED;
    }

    uint8_t result_validation[1] = { *result };
    status = sign(result_validation, enclave_signature, sizeof(result_validation));
    if (status != SGX_SUCCESS) {
        printf("Failed to sign the message: %d\n", status);
        return status;
    }

    return SGX_SUCCESS; 
}

uint32_t convert_string_to_uint32_t(uint8_t* str) {
    char* endptr;
    long int value = strtol((const char*)str, &endptr, 10);
    
    // Check for conversion errors or invalid input
    if (*endptr != '\0' || value < 0 || value > UINT32_MAX) {
        // Handle error or invalid input case
        // Return an appropriate value or indicate an error condition
    }
    
    return (uint32_t)value;
}

/*
 *** Migration functions ***
*/
sgx_status_t ecall_migration_prepare_record(
    uint32_t client_id, 
    uint8_t **encrypted, 
    size_t *encrypted_sz, 
    sgx_aes_gcm_128bit_tag_t **out_mac) {

    if (!encrypted || !encrypted_sz || !out_mac) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    printf("ecall_migration_prepare_record called on enclave with version %d for client %d\n", ENCLAVE_VERSION, client_id);

    sgx_status_t retval = SGX_SUCCESS;
    int ret = 0;
    int ocall_return = 0;

    size_t sealed_data_size = 0;

    sgx_status_t ocall_status = ocall_get_sealed_data_size(&ocall_return, (int) client_id, &sealed_data_size);
    if (ocall_status != SGX_SUCCESS) {
        printf("Error calling ocall: %d\n", ocall_status);
        return ocall_status;
    }
    if (ocall_return != 0) {
        printf("Error in ocall: %d\n", ocall_return);
        return SGX_ERROR_UNEXPECTED;
    }

    // remove 1 from size, so we don't read the version
    uint8_t *sealed_data = (uint8_t*) malloc(sealed_data_size);
    if (sealed_data == NULL) {
        printf("error allocating memory for sealed data\n");
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    ocall_status = ocall_read_sealed_data(&ocall_return, (int) client_id, sealed_data, sealed_data_size);
    if (ocall_status != SGX_SUCCESS) {
        printf("error calling ocall: %d\n", ocall_status);
        return ocall_status;
    }
    if (ocall_return != 0) {
        printf("error in ocall: %d\n", ocall_return);
        return SGX_ERROR_UNEXPECTED;
    }

    uint8_t card_enclave_version = sealed_data[sealed_data_size - 1]; 
    printf("enclave: version %d\n", card_enclave_version);
    if (card_enclave_version != ENCLAVE_VERSION) {
        printf("** card was sealed with a different enclave version (please run a migration)**\n");
        return SGX_ERROR_UNEXPECTED;
    }

    uint8_t *unsealed = NULL;
    size_t unsealed_size = 0;
    uint8_t *aad = NULL;
    size_t aad_size = 0;

    retval = unseal(sealed_data, sealed_data_size, &unsealed, &unsealed_size, &aad, &aad_size);
    if (retval != SGX_SUCCESS) {
        printf("Error unsealing data: %d\n", retval);
        free(sealed_data);
        return retval;
    }

    if (aad_size < sizeof(uint32_t) || client_id != *(uint32_t*) aad) {
        free(sealed_data);
        free(unsealed);
        return SGX_ERROR_MAC_MISMATCH;
    }

    *encrypted = (uint8_t*) malloc(unsealed_size - 1);
    if (*encrypted == NULL) {
        free(sealed_data);
        free(unsealed);
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    sgx_aes_gcm_128bit_tag_t *mac = NULL;
    mac = (sgx_aes_gcm_128bit_tag_t*) malloc(sizeof(sgx_aes_gcm_128bit_tag_t));
    if (!mac) {
        free(sealed_data);
        free(unsealed);
        free(*encrypted);
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    sgx_status_t encryption_result = encrypt_data(
        &dh_key, 
        unsealed, 
        (uint32_t) (unsealed_size - 1), 
        *encrypted,
        mac
    );

    if (encryption_result != SGX_SUCCESS) {
        free(sealed_data);
        free(unsealed);
        free(*encrypted);
        free(mac);
        return encryption_result;
    }

    *out_mac = mac;
    *encrypted_sz = unsealed_size - 1;

    free(sealed_data);
    free(unsealed);

    return SGX_SUCCESS;
}

sgx_status_t ecall_migration_finalize(uint8_t *encrypted, size_t encrypted_sz, uint8_t *mac, size_t mac_sz) {
    printf("ecall_migration_finalize called\n");

    if (!encrypted || !mac || mac_sz != sizeof(sgx_aes_gcm_128bit_tag_t)) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    sgx_status_t retval = SGX_SUCCESS;
    int ret = 0;
    int ocall_return = 0;

    uint8_t *decrypted = (uint8_t*) malloc(sizeof(uint8_t) * encrypted_sz);
    if (!decrypted) {
        printf("Error: Out of memory.\n");
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    uint8_t *iv = (uint8_t *) calloc(IV_SIZE, sizeof(uint8_t));
    if (!iv) {
        printf("Error: Out of memory.\n");
        free(decrypted);
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    ret = sgx_rijndael128GCM_decrypt(
        &dh_key, 
        encrypted, 
        encrypted_sz, 
        decrypted, 
        iv, 
        IV_SIZE, 
        NULL, 
        0, 
        (sgx_aes_gcm_128bit_tag_t*)mac
    );

    free(iv);

    if (ret != SGX_SUCCESS) {
        printf("error while decrypting");
        free(decrypted);
        return SGX_ERROR_UNEXPECTED;
    }

    Card card = deserialize(std::vector<uint8_t>(decrypted, decrypted + encrypted_sz));
    printf("card decrypted on enclave with version %d, for client %d\n", ENCLAVE_VERSION, card.client_id);

    int cardseal_result = ecall_encrypt_card(&card);

    free(decrypted);
    if (cardseal_result != 0) {
        return SGX_ERROR_UNEXPECTED;
    }

    return SGX_SUCCESS;
}

/*
 *** Diffie-Hellman Key-Exchange functions ***
*/
void ecall_init_session_initiator(sgx_status_t *dh_status) {
  *dh_status = sgx_dh_init_session(SGX_DH_SESSION_INITIATOR, &dh_session);
}
void ecall_init_session_responder(sgx_status_t *dh_status) {
  *dh_status = sgx_dh_init_session(SGX_DH_SESSION_RESPONDER, &dh_session);
}
void ecall_create_message1(sgx_dh_msg1_t *msg1, sgx_status_t *dh_status) {
  *dh_status = sgx_dh_responder_gen_msg1(msg1, &dh_session);
}
void ecall_process_message1(const sgx_dh_msg1_t *msg1, sgx_dh_msg2_t *msg2, sgx_status_t *dh_status) {
  *dh_status = sgx_dh_initiator_proc_msg1(msg1, msg2, &dh_session);
}
void ecall_process_message2(const sgx_dh_msg2_t *msg2, sgx_dh_msg3_t *msg3, sgx_status_t *dh_status)
{
  *dh_status = sgx_dh_responder_proc_msg2(msg2, msg3, &dh_session, &dh_key, &dh_identity);
}
void ecall_process_message3(const sgx_dh_msg3_t *msg3, sgx_status_t *dh_status) {
  *dh_status = sgx_dh_initiator_proc_msg3(msg3, &dh_session, &dh_key, &dh_identity);
}
