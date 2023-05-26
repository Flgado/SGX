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

typedef struct ms_generate_ecc_key_pair_t {
	sgx_status_t ms_retval;
	PublicKey* ms_enclave_public_key;
	size_t ms_key_size;
} ms_generate_ecc_key_pair_t;

typedef struct ms_teste_t {
	sgx_status_t ms_retval;
	const unsigned char* ms_msg;
	Signature* ms_enclave_signature;
	size_t ms_msg_size;
} ms_teste_t;

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

sgx_status_t generate_ecc_key_pair(sgx_enclave_id_t eid, sgx_status_t* retval, PublicKey* enclave_public_key, size_t key_size)
{
	sgx_status_t status;
	ms_generate_ecc_key_pair_t ms;
	ms.ms_enclave_public_key = enclave_public_key;
	ms.ms_key_size = key_size;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t teste(sgx_enclave_id_t eid, sgx_status_t* retval, const unsigned char* msg, Signature* enclave_signature, size_t msg_size)
{
	sgx_status_t status;
	ms_teste_t ms;
	ms.ms_msg = msg;
	ms.ms_enclave_signature = enclave_signature;
	ms.ms_msg_size = msg_size;
	status = sgx_ecall(eid, 5, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

