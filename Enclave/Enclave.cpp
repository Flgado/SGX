#include "Enclave_t.h"
#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "serializer.h"
#include "encryption.h"

sgx_ec256_private_t private_key;
void _print_values(char *format, ...) {
    char buff[128];
    va_list args;
    va_start(args, format);
    vsnprintf(buff, sizeof(buff), format, args);
    va_end(args);
    ocall_print(buff);
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

    status = sgx_seal_data(
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
        _print_values("seal failed: %d\n", status);
        return status;
    }

    // writes result into file
    int ocall_return;
    ocall_write_sealed_data(&ocall_return, card->client_id, sealed_data, sealed_data_size);
    if (ocall_return != 0) {
        _print_values("Error in ocall: %d\n", ocall_return);
        return SGX_ERROR_UNEXPECTED;
    }

    free(sealed_data);
}

int ecall_setup_card(uint32_t client_id, uint8_t *array, size_t array_size) {
    sgx_status_t status;

    Card card;
    card.client_id = client_id;

    for (int i = 0; i < array_size; i++) {
        uint8_t value;
        status = sgx_read_rand(&value, sizeof(value));
        if (status != SGX_SUCCESS) {
            ocall_print("Error generating random number");
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
        _print_values("failed to decrypt\n");
    }

    uint32_t client_id = convert_string_to_uint32_t(enc_client_id);

    sgx_status_t retval = SGX_SUCCESS;
    int ret = 0;
    int ocall_return = 0;

    size_t sealed_data_size = 0;

    sgx_status_t ocall_status = ocall_get_sealed_data_size(&ocall_return, (int) client_id, &sealed_data_size);
    if (ocall_status != SGX_SUCCESS) {
        _print_values("Error calling ocall: %d\n", ocall_status);
        return ocall_status;
    }
    if (ocall_return != 0) {
        _print_values("Error in ocall: %d\n", ocall_return);
        return SGX_ERROR_UNEXPECTED;
    }

    uint8_t *sealed_data = (uint8_t*) malloc(sealed_data_size);
    if (sealed_data == NULL) {
        _print_values("Error allocating memory for sealed data\n");
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    ocall_status = ocall_read_sealed_data(&ocall_return, (int) client_id, sealed_data, sealed_data_size);
    if (ocall_status != SGX_SUCCESS) {
        _print_values("Error calling ocall: %d\n", ocall_status);
        return ocall_status;
    }
    if (ocall_return != 0) {
        _print_values("Error in ocall: %d\n", ocall_return);
        return SGX_ERROR_UNEXPECTED;
    }

    uint8_t *unsealed = NULL;
    size_t unsealed_size = 0;
    uint8_t *aad = NULL;
    size_t aad_size = 0;

    retval = _unseal(sealed_data, sealed_data_size, &unsealed, &unsealed_size, &aad, &aad_size);
    if (retval != SGX_SUCCESS) {
        _print_values("Error unsealing data: %d\n", retval);
        return retval;
    }

    if (client_id != *(uint32_t*) aad) {
        _print_values("failed signature verification\n");
        return retval;
    }

    Card card = deserialize(std::vector<uint8_t>(unsealed, unsealed + unsealed_size));
    if (!card.log.empty()) {
        for (const auto &entry : card.log) {
            uint64_t ts = (uint64_t) entry.first;
            bool validation_result = (bool) entry.second;

            char buffer[1000];
            snprintf(buffer, sizeof(buffer), "timestamp: %lu, validation result: %d", ts, validation_result);
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
        _print_values("Error calling ocall: %d\n", ocall_status);
        return ocall_status;
    }
    if (ocall_return != 0) {
        _print_values("Error in ocall: %d\n", ocall_return);
        return SGX_ERROR_UNEXPECTED;
    }

    uint8_t *sealed_data = (uint8_t*) malloc(sealed_data_size);
    if (sealed_data == NULL) {
        _print_values("Error allocating memory for sealed data\n");
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    ocall_status = ocall_read_sealed_data(&ocall_return, (int) client_id, sealed_data, sealed_data_size);
    if (ocall_status != SGX_SUCCESS) {
        _print_values("Error calling ocall: %d\n", ocall_status);
        return ocall_status;
    }
    if (ocall_return != 0) {
        _print_values("Error in ocall: %d\n", ocall_return);
        return SGX_ERROR_UNEXPECTED;
    }

    uint8_t *unsealed = NULL;
    size_t unsealed_size = 0;
    uint8_t *aad = NULL;
    size_t aad_size = 0;

    retval = _unseal(sealed_data, sealed_data_size, &unsealed, &unsealed_size, &aad, &aad_size);
    if (retval != SGX_SUCCESS) {
        _print_values("Error unsealing data: %d\n", retval);
        return retval;
    }

    if (client_id != *(uint32_t*) aad) {
        _print_values("failed signature verification\n");
        return retval;
    }

    Card card = deserialize(std::vector<uint8_t>(unsealed, unsealed + unsealed_size));
    if (!card.log.empty()) {
        if (timestamp <= card.log.back().first) {
            free(sealed_data);
            free(unsealed);
            free(aad);

            _print_values("TIMESTAMP VALIDATION FAILED!\n");
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


sgx_status_t teste(const unsigned char* msg, Signature *enclave_singature, size_t message_size)
{
    sgx_ecc_state_handle_t ecc_handle;

    // Open ECC context
    sgx_status_t status = sgx_ecc256_open_context(&ecc_handle);
    // Sign "hello world" message
    //const uint8_t message[] = "hello world";
    sgx_ec256_signature_t signature;
    status = sgx_ecdsa_sign(msg, message_size, &private_key, &signature, ecc_handle);
    if (status != SGX_SUCCESS) {
        _print_values("Failed to sign the message: %d\n", status);
        sgx_ecc256_close_context(ecc_handle);
        return status;
    }

    memcpy(enclave_singature->r, (uint8_t*)signature.x, 32);
    memcpy(enclave_singature->s, (uint8_t*)signature.y, 32);
    
    // Close ECC context
    status = sgx_ecc256_close_context(ecc_handle);
}

sgx_status_t generate_ecc_key_pair(PublicKey *public_key_to_parse, size_t size) {
    
    sgx_ec256_public_t public_key;
    sgx_ecc_state_handle_t ecc_handle;

    // Open ECC context
    sgx_status_t status = sgx_ecc256_open_context(&ecc_handle);
    if (status != SGX_SUCCESS) {
        _print_values("Failed to open ECC context: %d\n", status);
        return status;
    }
    // Generate ECC key pair
    status = sgx_ecc256_create_key_pair(&private_key, &public_key, ecc_handle);
    if (status != SGX_SUCCESS) {
        _print_values("Failed to generate ECC key pair: %d\n", status);
        sgx_ecc256_close_context(ecc_handle);
        return status;
    }

    // Copy the contents of public_key.gx to gx
    memcpy(public_key_to_parse->gx, public_key.gx, sizeof(public_key.gx));

    // Copy the contents of public_key.gy to gy
    memcpy(public_key_to_parse->gy, public_key.gy, sizeof(public_key.gy));

    // Close ECC context
    status = sgx_ecc256_close_context(ecc_handle);

    return SGX_SUCCESS;
}