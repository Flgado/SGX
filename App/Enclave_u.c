#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_insert_matrix_card_t {
	uint8_t* ms_data;
	uint32_t ms_data_size;
} ms_ecall_insert_matrix_card_t;

typedef struct ms_ecall_opendb_t {
	const char* ms_db_name;
	size_t ms_db_name_len;
} ms_ecall_opendb_t;

typedef struct ms_ecall_execute_sql_t {
	const char* ms_sql;
	size_t ms_sql_len;
} ms_ecall_execute_sql_t;

typedef struct ms_ecall_get_text_size_t {
	const char* ms_sql;
	size_t ms_sql_len;
	int* ms_size;
} ms_ecall_get_text_size_t;

typedef struct ms_ecall_get_text_value_t {
	const char* ms_sql;
	size_t ms_sql_len;
	uint8_t* ms_data_from_db;
	uint32_t ms_data_from_db_size;
} ms_ecall_get_text_value_t;

typedef struct ms_ecall_get_current_stored_value_t {
	uint8_t* ms_result;
} ms_ecall_get_current_stored_value_t;

typedef struct ms_generate_matrix_card_values_t {
	int ms_retval;
	uint8_t* ms_array;
	size_t ms_array_size;
} ms_generate_matrix_card_values_t;

typedef struct ms_get_sealed_data_size_t {
	uint32_t ms_retval;
	uint32_t ms_fsize;
} ms_get_sealed_data_size_t;

typedef struct ms_seal_data_t {
	sgx_status_t ms_retval;
	uint8_t* ms_plaintext;
	size_t ms_plaintext_size;
	uint8_t* ms_sealed_data;
	size_t ms_sealed_size;
} ms_seal_data_t;

typedef struct ms_unseal_data_t {
	sgx_status_t ms_retval;
	uint8_t* ms_sealed_data;
	size_t ms_sealed_size;
	uint8_t* ms_plaintext;
	size_t ms_plaintext_size;
} ms_unseal_data_t;

typedef struct ms_ecall_validate_coords_t {
	sgx_status_t ms_retval;
	uint32_t ms_client_id;
	Coords* ms_coords;
	size_t ms_num_coords;
	uint8_t* ms_result;
} ms_ecall_validate_coords_t;

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

typedef struct ms_ocall_lstat_t {
	int ms_retval;
	int ocall_errno;
	const char* ms_path;
	struct stat* ms_buf;
	size_t ms_size;
} ms_ocall_lstat_t;

typedef struct ms_ocall_stat_t {
	int ms_retval;
	const char* ms_path;
	struct stat* ms_buf;
	size_t ms_size;
} ms_ocall_stat_t;

typedef struct ms_ocall_fstat_t {
	int ms_retval;
	int ms_fd;
	struct stat* ms_buf;
	size_t ms_size;
} ms_ocall_fstat_t;

typedef struct ms_ocall_ftruncate_t {
	int ms_retval;
	int ms_fd;
	off_t ms_length;
} ms_ocall_ftruncate_t;

typedef struct ms_ocall_getcwd_t {
	char* ms_retval;
	int ocall_errno;
	char* ms_buf;
	size_t ms_size;
} ms_ocall_getcwd_t;

typedef struct ms_ocall_getpid_t {
	int ms_retval;
} ms_ocall_getpid_t;

typedef struct ms_ocall_getuid_t {
	int ms_retval;
} ms_ocall_getuid_t;

typedef struct ms_ocall_getenv_t {
	char* ms_retval;
	const char* ms_name;
} ms_ocall_getenv_t;

typedef struct ms_ocall_open64_t {
	int ms_retval;
	const char* ms_filename;
	int ms_flags;
	mode_t ms_mode;
} ms_ocall_open64_t;

typedef struct ms_ocall_close_t {
	int ms_retval;
	int ms_fd;
} ms_ocall_close_t;

typedef struct ms_ocall_lseek64_t {
	off_t ms_retval;
	int ocall_errno;
	int ms_fd;
	off_t ms_offset;
	int ms_whence;
} ms_ocall_lseek64_t;

typedef struct ms_ocall_read_t {
	int ms_retval;
	int ocall_errno;
	int ms_fd;
	void* ms_buf;
	size_t ms_count;
} ms_ocall_read_t;

typedef struct ms_ocall_write_t {
	int ms_retval;
	int ocall_errno;
	int ms_fd;
	const void* ms_buf;
	size_t ms_count;
} ms_ocall_write_t;

typedef struct ms_ocall_fsync_t {
	int ms_retval;
	int ms_fd;
} ms_ocall_fsync_t;

typedef struct ms_ocall_fcntl_t {
	int ms_retval;
	int ocall_errno;
	int ms_fd;
	int ms_cmd;
	void* ms_arg;
	size_t ms_size;
} ms_ocall_fcntl_t;

typedef struct ms_ocall_fcntl64_t {
	int ms_retval;
	int ocall_errno;
	int ms_fd;
	int ms_cmd;
	void* ms_arg;
	size_t ms_size;
} ms_ocall_fcntl64_t;

typedef struct ms_ocall_unlink_t {
	int ms_retval;
	const char* ms_pathname;
} ms_ocall_unlink_t;

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

static sgx_status_t SGX_CDECL Enclave_ocall_lstat(void* pms)
{
	ms_ocall_lstat_t* ms = SGX_CAST(ms_ocall_lstat_t*, pms);
	ms->ms_retval = ocall_lstat(ms->ms_path, ms->ms_buf, ms->ms_size);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_stat(void* pms)
{
	ms_ocall_stat_t* ms = SGX_CAST(ms_ocall_stat_t*, pms);
	ms->ms_retval = ocall_stat(ms->ms_path, ms->ms_buf, ms->ms_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_fstat(void* pms)
{
	ms_ocall_fstat_t* ms = SGX_CAST(ms_ocall_fstat_t*, pms);
	ms->ms_retval = ocall_fstat(ms->ms_fd, ms->ms_buf, ms->ms_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_ftruncate(void* pms)
{
	ms_ocall_ftruncate_t* ms = SGX_CAST(ms_ocall_ftruncate_t*, pms);
	ms->ms_retval = ocall_ftruncate(ms->ms_fd, ms->ms_length);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_getcwd(void* pms)
{
	ms_ocall_getcwd_t* ms = SGX_CAST(ms_ocall_getcwd_t*, pms);
	ms->ms_retval = ocall_getcwd(ms->ms_buf, ms->ms_size);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_getpid(void* pms)
{
	ms_ocall_getpid_t* ms = SGX_CAST(ms_ocall_getpid_t*, pms);
	ms->ms_retval = ocall_getpid();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_getuid(void* pms)
{
	ms_ocall_getuid_t* ms = SGX_CAST(ms_ocall_getuid_t*, pms);
	ms->ms_retval = ocall_getuid();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_getenv(void* pms)
{
	ms_ocall_getenv_t* ms = SGX_CAST(ms_ocall_getenv_t*, pms);
	ms->ms_retval = ocall_getenv(ms->ms_name);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_open64(void* pms)
{
	ms_ocall_open64_t* ms = SGX_CAST(ms_ocall_open64_t*, pms);
	ms->ms_retval = ocall_open64(ms->ms_filename, ms->ms_flags, ms->ms_mode);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_close(void* pms)
{
	ms_ocall_close_t* ms = SGX_CAST(ms_ocall_close_t*, pms);
	ms->ms_retval = ocall_close(ms->ms_fd);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_lseek64(void* pms)
{
	ms_ocall_lseek64_t* ms = SGX_CAST(ms_ocall_lseek64_t*, pms);
	ms->ms_retval = ocall_lseek64(ms->ms_fd, ms->ms_offset, ms->ms_whence);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_read(void* pms)
{
	ms_ocall_read_t* ms = SGX_CAST(ms_ocall_read_t*, pms);
	ms->ms_retval = ocall_read(ms->ms_fd, ms->ms_buf, ms->ms_count);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_write(void* pms)
{
	ms_ocall_write_t* ms = SGX_CAST(ms_ocall_write_t*, pms);
	ms->ms_retval = ocall_write(ms->ms_fd, ms->ms_buf, ms->ms_count);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_fsync(void* pms)
{
	ms_ocall_fsync_t* ms = SGX_CAST(ms_ocall_fsync_t*, pms);
	ms->ms_retval = ocall_fsync(ms->ms_fd);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_fcntl(void* pms)
{
	ms_ocall_fcntl_t* ms = SGX_CAST(ms_ocall_fcntl_t*, pms);
	ms->ms_retval = ocall_fcntl(ms->ms_fd, ms->ms_cmd, ms->ms_arg, ms->ms_size);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_fcntl64(void* pms)
{
	ms_ocall_fcntl64_t* ms = SGX_CAST(ms_ocall_fcntl64_t*, pms);
	ms->ms_retval = ocall_fcntl64(ms->ms_fd, ms->ms_cmd, ms->ms_arg, ms->ms_size);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_unlink(void* pms)
{
	ms_ocall_unlink_t* ms = SGX_CAST(ms_ocall_unlink_t*, pms);
	ms->ms_retval = ocall_unlink(ms->ms_pathname);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[22];
} ocall_table_Enclave = {
	22,
	{
		(void*)Enclave_ocall_print,
		(void*)Enclave_ocall_println_string,
		(void*)Enclave_ocall_print_string,
		(void*)Enclave_ocall_print_error,
		(void*)Enclave_ocall_text_print,
		(void*)Enclave_ocall_lstat,
		(void*)Enclave_ocall_stat,
		(void*)Enclave_ocall_fstat,
		(void*)Enclave_ocall_ftruncate,
		(void*)Enclave_ocall_getcwd,
		(void*)Enclave_ocall_getpid,
		(void*)Enclave_ocall_getuid,
		(void*)Enclave_ocall_getenv,
		(void*)Enclave_ocall_open64,
		(void*)Enclave_ocall_close,
		(void*)Enclave_ocall_lseek64,
		(void*)Enclave_ocall_read,
		(void*)Enclave_ocall_write,
		(void*)Enclave_ocall_fsync,
		(void*)Enclave_ocall_fcntl,
		(void*)Enclave_ocall_fcntl64,
		(void*)Enclave_ocall_unlink,
	}
};
sgx_status_t ecall_insert_matrix_card(sgx_enclave_id_t eid, uint8_t* data, uint32_t data_size)
{
	sgx_status_t status;
	ms_ecall_insert_matrix_card_t ms;
	ms.ms_data = data;
	ms.ms_data_size = data_size;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_opendb(sgx_enclave_id_t eid, const char* db_name)
{
	sgx_status_t status;
	ms_ecall_opendb_t ms;
	ms.ms_db_name = db_name;
	ms.ms_db_name_len = db_name ? strlen(db_name) + 1 : 0;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_execute_sql(sgx_enclave_id_t eid, const char* sql)
{
	sgx_status_t status;
	ms_ecall_execute_sql_t ms;
	ms.ms_sql = sql;
	ms.ms_sql_len = sql ? strlen(sql) + 1 : 0;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_get_text_size(sgx_enclave_id_t eid, const char* sql, int* size)
{
	sgx_status_t status;
	ms_ecall_get_text_size_t ms;
	ms.ms_sql = sql;
	ms.ms_sql_len = sql ? strlen(sql) + 1 : 0;
	ms.ms_size = size;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_get_text_value(sgx_enclave_id_t eid, const char* sql, uint8_t* data_from_db, uint32_t data_from_db_size)
{
	sgx_status_t status;
	ms_ecall_get_text_value_t ms;
	ms.ms_sql = sql;
	ms.ms_sql_len = sql ? strlen(sql) + 1 : 0;
	ms.ms_data_from_db = data_from_db;
	ms.ms_data_from_db_size = data_from_db_size;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_close_db(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 5, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_get_current_stored_value(sgx_enclave_id_t eid, uint8_t* result)
{
	sgx_status_t status;
	ms_ecall_get_current_stored_value_t ms;
	ms.ms_result = result;
	status = sgx_ecall(eid, 6, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t generate_matrix_card_values(sgx_enclave_id_t eid, int* retval, uint8_t* array, size_t array_size)
{
	sgx_status_t status;
	ms_generate_matrix_card_values_t ms;
	ms.ms_array = array;
	ms.ms_array_size = array_size;
	status = sgx_ecall(eid, 7, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t get_sealed_data_size(sgx_enclave_id_t eid, uint32_t* retval, uint32_t fsize)
{
	sgx_status_t status;
	ms_get_sealed_data_size_t ms;
	ms.ms_fsize = fsize;
	status = sgx_ecall(eid, 8, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t seal_data(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* plaintext, size_t plaintext_size, uint8_t* sealed_data, size_t sealed_size)
{
	sgx_status_t status;
	ms_seal_data_t ms;
	ms.ms_plaintext = plaintext;
	ms.ms_plaintext_size = plaintext_size;
	ms.ms_sealed_data = sealed_data;
	ms.ms_sealed_size = sealed_size;
	status = sgx_ecall(eid, 9, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t unseal_data(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* sealed_data, size_t sealed_size, uint8_t* plaintext, size_t plaintext_size)
{
	sgx_status_t status;
	ms_unseal_data_t ms;
	ms.ms_sealed_data = sealed_data;
	ms.ms_sealed_size = sealed_size;
	ms.ms_plaintext = plaintext;
	ms.ms_plaintext_size = plaintext_size;
	status = sgx_ecall(eid, 10, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_validate_coords(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t client_id, Coords* coords, size_t num_coords, uint8_t* result)
{
	sgx_status_t status;
	ms_ecall_validate_coords_t ms;
	ms.ms_client_id = client_id;
	ms.ms_coords = coords;
	ms.ms_num_coords = num_coords;
	ms.ms_result = result;
	status = sgx_ecall(eid, 11, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

