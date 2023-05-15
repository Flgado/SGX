#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_generate_matrix_card_values_t {
	int ms_retval;
	uint32_t ms_client_id;
	uint8_t* ms_array;
	size_t ms_array_size;
} ms_generate_matrix_card_values_t;

typedef struct ms_ecall_validate_coords_t {
	sgx_status_t ms_retval;
	uint32_t ms_client_id;
	Coords* ms_coords;
	size_t ms_num_coords;
	uint8_t* ms_result;
	uint64_t ms_timestamp;
} ms_ecall_validate_coords_t;

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

typedef struct ms_ocall_println_string_t {
	const char* ms_str;
} ms_ocall_println_string_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_ocall_print_error_t {
	const char* ms_str;
} ms_ocall_print_error_t;

typedef struct ms_ocall_text_print_t {
	uint8_t* ms_data;
	uint32_t ms_data_size;
} ms_ocall_text_print_t;

typedef struct ms_ocall_copy_file_t {
	const char* ms_src_path;
	const char* ms_dest_path;
} ms_ocall_copy_file_t;

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

static sgx_status_t SGX_CDECL Enclave_ocall_println_string(void* pms)
{
	ms_ocall_println_string_t* ms = SGX_CAST(ms_ocall_println_string_t*, pms);
	ocall_println_string(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_print_error(void* pms)
{
	ms_ocall_print_error_t* ms = SGX_CAST(ms_ocall_print_error_t*, pms);
	ocall_print_error(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_text_print(void* pms)
{
	ms_ocall_text_print_t* ms = SGX_CAST(ms_ocall_text_print_t*, pms);
	ocall_text_print(ms->ms_data, ms->ms_data_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_copy_file(void* pms)
{
	ms_ocall_copy_file_t* ms = SGX_CAST(ms_ocall_copy_file_t*, pms);
	ocall_copy_file(ms->ms_src_path, ms->ms_dest_path);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[9];
} ocall_table_Enclave = {
	9,
	{
		(void*)Enclave_ocall_write_sealed_data,
		(void*)Enclave_ocall_get_sealed_data_size,
		(void*)Enclave_ocall_read_sealed_data,
		(void*)Enclave_ocall_print,
		(void*)Enclave_ocall_println_string,
		(void*)Enclave_ocall_print_string,
		(void*)Enclave_ocall_print_error,
		(void*)Enclave_ocall_text_print,
		(void*)Enclave_ocall_copy_file,
	}
};
sgx_status_t generate_matrix_card_values(sgx_enclave_id_t eid, int* retval, uint32_t client_id, uint8_t* array, size_t array_size)
{
	sgx_status_t status;
	ms_generate_matrix_card_values_t ms;
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

