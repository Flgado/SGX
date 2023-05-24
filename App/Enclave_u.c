#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_setup_card_t {
	int ms_retval;
	uint32_t ms_client_id;
	uint8_t* ms_array;
	size_t ms_array_size;
} ms_ecall_setup_card_t;

typedef struct ms_ecall_validate_coords_t {
	sgx_status_t ms_retval;
	uint32_t ms_client_id;
	Coords* ms_coords;
	size_t ms_num_coords;
	uint8_t* ms_result;
	uint64_t ms_timestamp;
} ms_ecall_validate_coords_t;

typedef struct ms_ecall_print_logs_t {
	sgx_status_t ms_retval;
	uint8_t* ms_enc_client_id;
	int ms_enc_sz;
	uint8_t* ms_tag;
} ms_ecall_print_logs_t;

typedef struct ms_ecall_generate_key_t {
	sgx_status_t ms_retval;
	uint8_t* ms_key;
	size_t ms_key_size;
} ms_ecall_generate_key_t;

typedef struct ms_ecall_migration_finalize_t {
	sgx_status_t ms_retval;
	uint8_t* ms_encrypted;
	size_t ms_encrypted_sz;
	uint8_t* ms_mac;
	size_t ms_mac_sz;
} ms_ecall_migration_finalize_t;

typedef struct ms_ecall_migration_prepare_record_t {
	sgx_status_t ms_retval;
	uint32_t ms_client_id;
	uint8_t** ms_encrypted;
	size_t* ms_encrypted_sz;
	sgx_aes_gcm_128bit_tag_t** ms_out_mac;
} ms_ecall_migration_prepare_record_t;

typedef struct ms_ecall_init_session_initiator_t {
	sgx_status_t* ms_dh_status;
} ms_ecall_init_session_initiator_t;

typedef struct ms_ecall_init_session_responder_t {
	sgx_status_t* ms_dh_status;
} ms_ecall_init_session_responder_t;

typedef struct ms_ecall_create_message1_t {
	sgx_dh_msg1_t* ms_msg1;
	sgx_status_t* ms_dh_status;
} ms_ecall_create_message1_t;

typedef struct ms_ecall_process_message1_t {
	const sgx_dh_msg1_t* ms_msg1;
	sgx_dh_msg2_t* ms_msg2;
	sgx_status_t* ms_dh_status;
} ms_ecall_process_message1_t;

typedef struct ms_ecall_process_message2_t {
	const sgx_dh_msg2_t* ms_msg2;
	sgx_dh_msg3_t* ms_msg3;
	sgx_status_t* ms_dh_status;
} ms_ecall_process_message2_t;

typedef struct ms_ecall_process_message3_t {
	const sgx_dh_msg3_t* ms_msg3;
	sgx_status_t* ms_dh_status;
} ms_ecall_process_message3_t;

typedef struct ms_ocall_write_sealed_data_t {
	int ms_retval;
	int ms_client_id;
	uint8_t* ms_sealed_data;
	size_t ms_sealed_data_size;
} ms_ocall_write_sealed_data_t;

typedef struct ms_ocall_get_sealed_data_size_t {
	int ms_retval;
	int ms_client_id;
	size_t* ms_file_size;
} ms_ocall_get_sealed_data_size_t;

typedef struct ms_ocall_read_sealed_data_t {
	int ms_retval;
	int ms_client_id;
	uint8_t* ms_data;
	size_t ms_data_size;
} ms_ocall_read_sealed_data_t;

typedef struct ms_ocall_print_t {
	const char* ms_str;
} ms_ocall_print_t;

static sgx_status_t SGX_CDECL Enclave_ocall_write_sealed_data(void* pms)
{
	ms_ocall_write_sealed_data_t* ms = SGX_CAST(ms_ocall_write_sealed_data_t*, pms);
	ms->ms_retval = ocall_write_sealed_data(ms->ms_client_id, ms->ms_sealed_data, ms->ms_sealed_data_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_get_sealed_data_size(void* pms)
{
	ms_ocall_get_sealed_data_size_t* ms = SGX_CAST(ms_ocall_get_sealed_data_size_t*, pms);
	ms->ms_retval = ocall_get_sealed_data_size(ms->ms_client_id, ms->ms_file_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_read_sealed_data(void* pms)
{
	ms_ocall_read_sealed_data_t* ms = SGX_CAST(ms_ocall_read_sealed_data_t*, pms);
	ms->ms_retval = ocall_read_sealed_data(ms->ms_client_id, ms->ms_data, ms->ms_data_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_print(void* pms)
{
	ms_ocall_print_t* ms = SGX_CAST(ms_ocall_print_t*, pms);
	ocall_print(ms->ms_str);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[4];
} ocall_table_Enclave = {
	4,
	{
		(void*)Enclave_ocall_write_sealed_data,
		(void*)Enclave_ocall_get_sealed_data_size,
		(void*)Enclave_ocall_read_sealed_data,
		(void*)Enclave_ocall_print,
	}
};
sgx_status_t ecall_setup_card(sgx_enclave_id_t eid, int* retval, uint32_t client_id, uint8_t* array, size_t array_size)
{
	sgx_status_t status;
	ms_ecall_setup_card_t ms;
	ms.ms_client_id = client_id;
	ms.ms_array = array;
	ms.ms_array_size = array_size;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_validate_coords(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t client_id, Coords* coords, size_t num_coords, uint8_t* result, uint64_t timestamp)
{
	sgx_status_t status;
	ms_ecall_validate_coords_t ms;
	ms.ms_client_id = client_id;
	ms.ms_coords = coords;
	ms.ms_num_coords = num_coords;
	ms.ms_result = result;
	ms.ms_timestamp = timestamp;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_print_logs(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* enc_client_id, int enc_sz, uint8_t* tag)
{
	sgx_status_t status;
	ms_ecall_print_logs_t ms;
	ms.ms_enc_client_id = enc_client_id;
	ms.ms_enc_sz = enc_sz;
	ms.ms_tag = tag;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_generate_key(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* key, size_t key_size)
{
	sgx_status_t status;
	ms_ecall_generate_key_t ms;
	ms.ms_key = key;
	ms.ms_key_size = key_size;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_migration_finalize(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* encrypted, size_t encrypted_sz, uint8_t* mac, size_t mac_sz)
{
	sgx_status_t status;
	ms_ecall_migration_finalize_t ms;
	ms.ms_encrypted = encrypted;
	ms.ms_encrypted_sz = encrypted_sz;
	ms.ms_mac = mac;
	ms.ms_mac_sz = mac_sz;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_migration_prepare_record(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t client_id, uint8_t** encrypted, size_t* encrypted_sz, sgx_aes_gcm_128bit_tag_t** out_mac)
{
	sgx_status_t status;
	ms_ecall_migration_prepare_record_t ms;
	ms.ms_client_id = client_id;
	ms.ms_encrypted = encrypted;
	ms.ms_encrypted_sz = encrypted_sz;
	ms.ms_out_mac = out_mac;
	status = sgx_ecall(eid, 5, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_init_session_initiator(sgx_enclave_id_t eid, sgx_status_t* dh_status)
{
	sgx_status_t status;
	ms_ecall_init_session_initiator_t ms;
	ms.ms_dh_status = dh_status;
	status = sgx_ecall(eid, 6, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_init_session_responder(sgx_enclave_id_t eid, sgx_status_t* dh_status)
{
	sgx_status_t status;
	ms_ecall_init_session_responder_t ms;
	ms.ms_dh_status = dh_status;
	status = sgx_ecall(eid, 7, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_create_message1(sgx_enclave_id_t eid, sgx_dh_msg1_t* msg1, sgx_status_t* dh_status)
{
	sgx_status_t status;
	ms_ecall_create_message1_t ms;
	ms.ms_msg1 = msg1;
	ms.ms_dh_status = dh_status;
	status = sgx_ecall(eid, 8, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_process_message1(sgx_enclave_id_t eid, const sgx_dh_msg1_t* msg1, sgx_dh_msg2_t* msg2, sgx_status_t* dh_status)
{
	sgx_status_t status;
	ms_ecall_process_message1_t ms;
	ms.ms_msg1 = msg1;
	ms.ms_msg2 = msg2;
	ms.ms_dh_status = dh_status;
	status = sgx_ecall(eid, 9, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_process_message2(sgx_enclave_id_t eid, const sgx_dh_msg2_t* msg2, sgx_dh_msg3_t* msg3, sgx_status_t* dh_status)
{
	sgx_status_t status;
	ms_ecall_process_message2_t ms;
	ms.ms_msg2 = msg2;
	ms.ms_msg3 = msg3;
	ms.ms_dh_status = dh_status;
	status = sgx_ecall(eid, 10, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_process_message3(sgx_enclave_id_t eid, const sgx_dh_msg3_t* msg3, sgx_status_t* dh_status)
{
	sgx_status_t status;
	ms_ecall_process_message3_t ms;
	ms.ms_msg3 = msg3;
	ms.ms_dh_status = dh_status;
	status = sgx_ecall(eid, 11, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_show_secret_key(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 12, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_hello_world(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 13, &ocall_table_Enclave, NULL);
	return status;
}

