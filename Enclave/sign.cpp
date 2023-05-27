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

    return SGX_SUCCESS;
}
