#ifndef DH_H_
#define DH_H_

#include "sgx_dh.h"

void ecall_init_session_initiator(sgx_status_t *dh_status);
void ecall_init_session_responder(sgx_status_t *dh_status);
void ecall_create_message1(sgx_dh_msg1_t *msg1, sgx_status_t *dh_status);
void ecall_process_message1(const sgx_dh_msg1_t *msg1, sgx_dh_msg2_t *msg2, sgx_status_t *dh_status);
void ecall_process_message2(const sgx_dh_msg2_t *msg2,sgx_dh_msg3_t *msg3,sgx_status_t *dh_status);
void ecall_process_message3(const sgx_dh_msg3_t *msg3, sgx_status_t *dh_status);

sgx_key_128bit_t get_dh_key(void); 

#endif