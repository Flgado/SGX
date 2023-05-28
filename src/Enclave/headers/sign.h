#ifndef SIGN_H_
#define SIGN_H_

#include "Enclave_t.h"
#include "sgx_trts.h"
#include "sgx_tseal.h"

sgx_status_t sign(const unsigned char* msg, ECDSA256Signature *enclave_singature, size_t message_size);
sgx_status_t ecall_generate_ecc_key_pair(ECDSA256PublicKey *public_key_to_parse, size_t ecc256_publicKey_size);

#endif