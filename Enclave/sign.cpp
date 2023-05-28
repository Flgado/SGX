#include "Enclave_t.h"
#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "Enclave_t.h"
#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "sgx_dh.h"
#include "headers/sign.h"
#include "headers/serializer.h"
#include "headers/encryption.h"
#include "headers/utils.h"
#include "headers/Enclave.h"

#define PRIVATE_KEY_SIZE 32

sgx_ec256_private_t enclave_private_key;

sgx_status_t sign(
    const unsigned char* msg, ECDSA256Signature *enclave_signature, size_t message_size) {

    sgx_ecc_state_handle_t ecc_handle;

    // Open ECC context
    sgx_status_t status = sgx_ecc256_open_context(&ecc_handle);

    sgx_ec256_signature_t signature;
    status = sgx_ecdsa_sign(msg, message_size, &enclave_private_key, &signature, ecc_handle);
    if (status != SGX_SUCCESS) {
        printf("Failed to sign the message: %d\n", status);
        status = sgx_ecc256_close_context(ecc_handle);
        return status;
    }

    memcpy(enclave_signature->r, (uint8_t*)signature.x, 32);
    memcpy(enclave_signature->s, (uint8_t*)signature.y, 32);

    // Close ECC context
    status = sgx_ecc256_close_context(ecc_handle);
    return SGX_SUCCESS;
}

sgx_status_t ecall_load_existing_private_key(void)
{
    int ocall_return = 0;

    size_t sealed_data_size = 0;
    ocall_get_signature_private_key_data_size(&ocall_return, &sealed_data_size);

    uint8_t *sealed_data = (uint8_t*) malloc(sealed_data_size);
    if (sealed_data == NULL) {
        printf("error allocating memory for sealed data in get_card_from_client_id()\n");
        return SGX_ERROR_UNEXPECTED;
    }

    sgx_status_t ocall_status = ocall_load_signature_private_key(&ocall_return, sealed_data, sealed_data_size);
    if (ocall_status != SGX_SUCCESS || ocall_return != 0) {
        printf("error calling ocall_read_sealed_data(): %d\n", ocall_status);
        free(sealed_data);
        return SGX_ERROR_UNEXPECTED;
    }

    uint32_t size = 32;
    sgx_sealed_data_t* sealed_data_ptr = (sgx_sealed_data_t*)sealed_data;

    sgx_status_t retval = sgx_unseal_data(sealed_data_ptr, NULL, 0, enclave_private_key.r, &size);

    
    if (retval != SGX_SUCCESS) {
        printf("error unsealing data: %d\n", retval);
        free(sealed_data);
        return retval;
    }
}

sgx_status_t ecall_generate_ecc_key_pair(ECDSA256PublicKey *public_key_to_parse, size_t ecc256_publicKey_size) {
    sgx_ec256_public_t public_key;
    sgx_ecc_state_handle_t ecc_handle;

    // Open ECC context
    sgx_status_t status = sgx_ecc256_open_context(&ecc_handle);
    if (status != SGX_SUCCESS) {
        printf("Failed to open ECC context: %d\n", status);
        return status;
    }
    // Generate ECC key pair
    status = sgx_ecc256_create_key_pair(&enclave_private_key, &public_key, ecc_handle);
    if (status != SGX_SUCCESS) {
        printf("Failed to generate ECC key pair");
        sgx_ecc256_close_context(ecc_handle);
        return status;
    }

    // Copy the contents of public_key.gx to gx
    memcpy(public_key_to_parse->gx, public_key.gx, sizeof(public_key.gx));

    // Copy the contents of public_key.gy to gy
    memcpy(public_key_to_parse->gy, public_key.gy, sizeof(public_key.gy));

    // Close ECC context
    status = sgx_ecc256_close_context(ecc_handle);

    // defaults
    sgx_attributes_t attributes;
    attributes.xfrm = SGX_XFRM_RESERVED;
    attributes.flags = 0xFF0000000000000B;

    uint32_t sealed_data_size = sgx_calc_sealed_data_size(0, PRIVATE_KEY_SIZE);

    sgx_sealed_data_t* sealed_data = (sgx_sealed_data_t*)malloc(sealed_data_size);

    status = sgx_seal_data_ex(
        KEY_POLICY,
        attributes,
        0,
        0, 
        NULL, 
        PRIVATE_KEY_SIZE, 
        enclave_private_key.r, 
        sealed_data_size, 
        sealed_data
    );

    int ocall_return;

    if(ocall_write_sealed_private_key(&ocall_return, (uint8_t*)sealed_data, sealed_data_size) != 0)
    {
        printf("Failed to Save sealed private key");
    }

    return SGX_SUCCESS;
}
