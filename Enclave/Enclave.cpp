#include "Enclave_t.h"
#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "sgx_dh.h"

#include "serializer.h"
#include "encryption.h"

#define ENCLAVE_VERSION 1
#define KEY_POLICY SGX_KEYPOLICY_MRSIGNER

sgx_dh_session_t dh_session;
sgx_key_128bit_t dh_key;
sgx_dh_session_enclave_identity_t dh_identity;

void ecall_show_secret_key(void) {
  printf("Enclave AEK:");
  for(int i = 0;i < 16;i++)
    printf(" %02X",0xFF & (int)dh_key[i]);
  printf("\n");
}

void ecall_hello_world(void) {
    printf("Hello world\n");
}

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

void ecall_process_message2(const sgx_dh_msg2_t *msg2,sgx_dh_msg3_t *msg3,sgx_status_t *dh_status)
{
  *dh_status = sgx_dh_responder_proc_msg2(msg2, msg3, &dh_session, &dh_key, &dh_identity);
}

void ecall_process_message3(const sgx_dh_msg3_t *msg3, sgx_status_t *dh_status) {
  *dh_status = sgx_dh_initiator_proc_msg3(msg3, &dh_session, &dh_key, &dh_identity);
}

sgx_status_t _unseal(uint8_t* sealed_data_ptr, size_t sealed_data_size, uint8_t** plaintext_ptr, size_t* plaintext_size_ptr, uint8_t** aad_ptr, size_t* aad_size_ptr) {
    sgx_status_t status;

    // Cast the sealed data pointer to sgx_sealed_data_t
    sgx_sealed_data_t* sealed_data = (sgx_sealed_data_t*)sealed_data_ptr;

    // Get the sizes of the aad and the plaintext
    uint32_t aad_size = sgx_get_add_mac_txt_len(sealed_data);
    uint32_t plaintext_size = sgx_get_encrypt_txt_len(sealed_data);

    // Allocate memory for the aad and the plaintext
    uint8_t* aad = (uint8_t*)malloc(aad_size);
    if(aad == NULL)
        return SGX_ERROR_OUT_OF_MEMORY;
    uint8_t* plaintext = (uint8_t*)malloc(plaintext_size);
    if(plaintext == NULL) {
        free(aad);
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    // Unseal the data
    status = sgx_unseal_data(sealed_data, aad, &aad_size, plaintext, &plaintext_size);
    if(SGX_SUCCESS != status) {
        free(aad);
        free(plaintext);
        return status;
    }

    // Return the aad and the plaintext
    *aad_ptr = aad;
    *aad_size_ptr = aad_size;
    *plaintext_ptr = plaintext;
    *plaintext_size_ptr = plaintext_size;
    return SGX_SUCCESS;
}

sgx_status_t ecall_migration_finalize(uint8_t *encrypted, size_t encrypted_sz, uint8_t *mac, size_t mac_sz) {
    printf("enclave: ecall_migration_finalize called\n");
    sgx_status_t retval = SGX_SUCCESS;
    int ret = 0;
    int ocall_return = 0;

    uint8_t *decrypted = (uint8_t*) malloc(sizeof(uint8_t) * encrypted_sz);
    uint8_t *iv = (uint8_t *) calloc(IV_SIZE, sizeof(uint8_t));

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

    if (ret != SGX_SUCCESS) {
        printf("error while decrypting");
    }

    Card card = deserialize(std::vector<uint8_t>(decrypted, decrypted + encrypted_sz));
    printf("card decrypted on enclave with version %d, for client %d\n", ENCLAVE_VERSION, card.client_id);
}

sgx_status_t ecall_migration_prepare_record(uint32_t client_id, uint8_t **encrypted, size_t *encrypted_sz, sgx_aes_gcm_128bit_tag_t **out_mac) {
    printf("enclave: ecall_migration_prepare_record called on enclave with version %d for client %d\n", ENCLAVE_VERSION, client_id);
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
        printf("Error allocating memory for sealed data\n");
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    ocall_status = ocall_read_sealed_data(&ocall_return, (int) client_id, sealed_data, sealed_data_size);
    if (ocall_status != SGX_SUCCESS) {
        printf("Error calling ocall: %d\n", ocall_status);
        return ocall_status;
    }
    if (ocall_return != 0) {
        printf("Error in ocall: %d\n", ocall_return);
        return SGX_ERROR_UNEXPECTED;
    }

    uint8_t card_enclave_version = sealed_data[sealed_data_size - 1]; 
    printf("enclave: version %d\n", card_enclave_version);
    if (card_enclave_version != ENCLAVE_VERSION) {
        printf("Card was sealed with a different enclave version");
        return SGX_ERROR_UNEXPECTED;
    }

    uint8_t *unsealed = NULL;
    size_t unsealed_size = 0;
    uint8_t *aad = NULL;
    size_t aad_size = 0;

    retval = _unseal(sealed_data, sealed_data_size, &unsealed, &unsealed_size, &aad, &aad_size);
    if (retval != SGX_SUCCESS) {
        printf("Error unsealing data: %d\n", retval);
        return retval;
    }

    if (client_id != *(uint32_t*) aad) {
        printf("failed signature verification\n");
        return retval;
    }

    *encrypted = (uint8_t*) malloc(unsealed_size - 1);
    if (*encrypted == NULL) {
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    *out_mac = (sgx_aes_gcm_128bit_tag_t*) malloc(sizeof(sgx_aes_gcm_128bit_tag_t));

    sgx_status_t encryption_result = encrypt_data(
        &dh_key, 
        unsealed, 
        (uint32_t) (unsealed_size - 1), 
        *encrypted,
        *out_mac
    );
    *encrypted_sz = unsealed_size - 1;

    if (encryption_result != SGX_SUCCESS) {
        printf("failed to encrypt\n");
    }
}

sgx_status_t _seal(uint8_t *plaintext, size_t plaintext_len, uint8_t *aad, size_t aad_len, uint8_t **sealed_data_ptr, size_t *sealed_data_size_ptr) {
    sgx_status_t status;

    uint32_t sealed_data_size = sgx_calc_sealed_data_size((uint32_t)aad_len, (uint32_t)plaintext_len);
    if(sealed_data_size == UINT32_MAX) {
        return SGX_ERROR_UNEXPECTED;
    }

    sgx_sealed_data_t* sealed_data = (sgx_sealed_data_t*)malloc(sealed_data_size);
    if(sealed_data == NULL) {
        return SGX_ERROR_OUT_OF_MEMORY;
    }

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

int ecall_encrypt_card(Card *card) {
    std::vector<uint8_t> serialized = serialize(*card);

    uint8_t *sealed_data = NULL;
    size_t sealed_data_size = 0;
    sgx_status_t status = _seal(
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
    memcpy(sealed_with_version, sealed_data, sealed_data_size);
    sealed_with_version[sealed_data_size] = ENCLAVE_VERSION;

    ocall_write_sealed_data(&ocall_return, card->client_id, sealed_with_version, sealed_data_size + 1);
    if (ocall_return != 0) {
        printf("Error in ocall: %d\n", ocall_return);
        return SGX_ERROR_UNEXPECTED;
    }

    free(sealed_data);
    free(sealed_with_version);
}

int ecall_setup_card(uint32_t client_id, uint8_t *array, size_t array_size) {
    sgx_status_t status;

    Card card;
    card.client_id = client_id;

    for (int i = 0; i < array_size; i++) {
        uint8_t value;
        status = sgx_read_rand(&value, sizeof(value));
        if (status != SGX_SUCCESS) {
            ocall_print("Error generating random number\n");
            return status;
        }
        array[i] = value;
        card.matrix_data[i] = value;
    }

    int ret = ecall_encrypt_card(&card);

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

sgx_status_t ecall_print_logs(uint8_t *enc_client_id, int enc_sz, uint8_t *tag) {
    sgx_status_t decryption_result = decrypt_data(enc_client_id, enc_sz, tag);
    if (decryption_result != SGX_SUCCESS) {
        printf("failed to decrypt\n");
    }

    uint32_t client_id = convert_string_to_uint32_t(enc_client_id);

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
        printf("Error allocating memory for sealed data\n");
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    ocall_status = ocall_read_sealed_data(&ocall_return, (int) client_id, sealed_data, sealed_data_size);
    if (ocall_status != SGX_SUCCESS) {
        printf("Error calling ocall: %d\n", ocall_status);
        return ocall_status;
    }
    if (ocall_return != 0) {
        printf("Error in ocall: %d\n", ocall_return);
        return SGX_ERROR_UNEXPECTED;
    }

    uint8_t card_enclave_version = sealed_data[sealed_data_size - 1]; 
    printf("enclave: version %d\n", card_enclave_version);
    if (card_enclave_version != ENCLAVE_VERSION) {
        printf("Card was sealed with a different enclave version");
        return SGX_ERROR_UNEXPECTED;
    }

    uint8_t *unsealed = NULL;
    size_t unsealed_size = 0;
    uint8_t *aad = NULL;
    size_t aad_size = 0;

    retval = _unseal(sealed_data, sealed_data_size, &unsealed, &unsealed_size, &aad, &aad_size);
    if (retval != SGX_SUCCESS) {
        printf("Error unsealing data: %d\n", retval);
        return retval;
    }

    if (client_id != *(uint32_t*) aad) {
        printf("failed signature verification\n");
        return retval;
    }

    Card card = deserialize(std::vector<uint8_t>(unsealed, unsealed + unsealed_size));
    if (!card.log.empty()) {
        for (const auto &entry : card.log) {
            uint64_t ts = (uint64_t) entry.first;
            bool validation_result = (bool) entry.second;

            char buffer[1000];
            snprintf(buffer, sizeof(buffer), "timestamp: %lu, validation result: %d\n", ts, validation_result);
            ocall_print(buffer);
        }
    }

    return retval;
}

sgx_status_t ecall_validate_coords(
    uint32_t client_id, 
    Coords *coords, 
    size_t num_coords, 
    uint8_t *result, 
    uint64_t timestamp) {
    
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

    uint8_t *sealed_data = (uint8_t*) malloc(sealed_data_size);
    if (sealed_data == NULL) {
        printf("Error allocating memory for sealed data\n");
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    ocall_status = ocall_read_sealed_data(&ocall_return, (int) client_id, sealed_data, sealed_data_size);
    if (ocall_status != SGX_SUCCESS) {
        printf("Error calling ocall: %d\n", ocall_status);
        return ocall_status;
    }
    if (ocall_return != 0) {
        printf("Error in ocall: %d\n", ocall_return);
        return SGX_ERROR_UNEXPECTED;
    }

    uint8_t card_enclave_version = sealed_data[sealed_data_size - 1]; 
    printf("enclave: version %d\n", card_enclave_version);
    if (card_enclave_version != ENCLAVE_VERSION) {
        printf("Card was sealed with a different enclave version");
        return SGX_ERROR_UNEXPECTED;
    }

    uint8_t *unsealed = NULL;
    size_t unsealed_size = 0;
    uint8_t *aad = NULL;
    size_t aad_size = 0;

    retval = _unseal(sealed_data, sealed_data_size, &unsealed, &unsealed_size, &aad, &aad_size);
    if (retval != SGX_SUCCESS) {
        printf("Error unsealing data: %d\n", retval);
        return retval;
    }

    if (client_id != *(uint32_t*) aad) {
        printf("failed signature verification\n");
        return retval;
    }

    Card card = deserialize(std::vector<uint8_t>(unsealed, unsealed + unsealed_size));
    if (!card.log.empty()) {
        if (timestamp <= card.log.back().first) {
            free(sealed_data);
            free(unsealed);
            free(aad);

            printf("TIMESTAMP VALIDATION FAILED!\n");
            return retval;
        }
    }

    ocall_print("[-] enclave::unsealed");

    *result = 1;
    for (size_t i = 0; i < num_coords; i++) {
        int idx = coords[i].y * 8 + coords[i].x;
        if (card.matrix_data[idx] != coords[i].val) {
            *result = 0;
        }
    }

    card.log.push_back({timestamp, *result});

    ecall_encrypt_card(&card);
    
    free(sealed_data);
    free(unsealed);
    free(aad);

    return retval; 
}