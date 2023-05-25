#include "Enclave_t.h"
#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "sgx_dh.h"
#include "dh.h"

sgx_key_128bit_t dh_key;
sgx_dh_session_t dh_session;
sgx_dh_session_enclave_identity_t dh_identity;

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

void ecall_process_message2(const sgx_dh_msg2_t *msg2, sgx_dh_msg3_t *msg3, sgx_status_t *dh_status) {
  *dh_status = sgx_dh_responder_proc_msg2(msg2, msg3, &dh_session, &dh_key, &dh_identity);
}

void ecall_process_message3(const sgx_dh_msg3_t *msg3, sgx_status_t *dh_status) {
  *dh_status = sgx_dh_initiator_proc_msg3(msg3, &dh_session, &dh_key, &dh_identity);
}

sgx_key_128bit_t get_dh_key(void) {
    return dh_key;
}