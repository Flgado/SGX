#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "sgx_dh.h"
#include "../ocall_types.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_WRITE_SEALED_DATA_DEFINED__
#define OCALL_WRITE_SEALED_DATA_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_write_sealed_data, (int client_id, uint8_t* sealed_data, size_t sealed_data_size));
#endif
#ifndef OCALL_GET_SEALED_DATA_SIZE_DEFINED__
#define OCALL_GET_SEALED_DATA_SIZE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_get_sealed_data_size, (int client_id, size_t* file_size));
#endif
#ifndef OCALL_READ_SEALED_DATA_DEFINED__
#define OCALL_READ_SEALED_DATA_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_read_sealed_data, (int client_id, uint8_t* data, size_t data_size));
#endif
#ifndef OCALL_PRINT_DEFINED__
#define OCALL_PRINT_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print, (const char* str));
#endif

sgx_status_t ecall_setup_card(sgx_enclave_id_t eid, int* retval, uint32_t client_id, uint8_t* array, size_t array_size);
sgx_status_t ecall_validate_coords(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t client_id, Coords* coords, size_t num_coords, uint8_t* result, uint64_t timestamp);
sgx_status_t ecall_print_logs(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* enc_client_id, int enc_sz, uint8_t* tag);
sgx_status_t ecall_generate_key(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* key, size_t key_size);
sgx_status_t ecall_migration_finalize(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* encrypted, size_t encrypted_sz, uint8_t* mac, size_t mac_sz);
sgx_status_t ecall_migration_prepare_record(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t client_id, uint8_t** encrypted, size_t* encrypted_sz, sgx_aes_gcm_128bit_tag_t** out_mac);
sgx_status_t ecall_init_session_initiator(sgx_enclave_id_t eid, sgx_status_t* dh_status);
sgx_status_t ecall_init_session_responder(sgx_enclave_id_t eid, sgx_status_t* dh_status);
sgx_status_t ecall_create_message1(sgx_enclave_id_t eid, sgx_dh_msg1_t* msg1, sgx_status_t* dh_status);
sgx_status_t ecall_process_message1(sgx_enclave_id_t eid, const sgx_dh_msg1_t* msg1, sgx_dh_msg2_t* msg2, sgx_status_t* dh_status);
sgx_status_t ecall_process_message2(sgx_enclave_id_t eid, const sgx_dh_msg2_t* msg2, sgx_dh_msg3_t* msg3, sgx_status_t* dh_status);
sgx_status_t ecall_process_message3(sgx_enclave_id_t eid, const sgx_dh_msg3_t* msg3, sgx_status_t* dh_status);
sgx_status_t ecall_show_secret_key(sgx_enclave_id_t eid);
sgx_status_t ecall_hello_world(sgx_enclave_id_t eid);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
