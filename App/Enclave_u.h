#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "../ocall_types.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _Coords
#define _Coords
typedef struct Coords {
	uint8_t x;
	uint8_t y;
	uint8_t val;
} Coords;
#endif

#ifndef OCALL_PRINT_DEFINED__
#define OCALL_PRINT_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print, (const char* str));
#endif
#ifndef OCALL_PRINTLN_STRING_DEFINED__
#define OCALL_PRINTLN_STRING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_println_string, (const char* str));
#endif
#ifndef OCALL_PRINT_STRING_DEFINED__
#define OCALL_PRINT_STRING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
#endif
#ifndef OCALL_PRINT_ERROR_DEFINED__
#define OCALL_PRINT_ERROR_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_error, (const char* str));
#endif
#ifndef OCALL_TEXT_PRINT_DEFINED__
#define OCALL_TEXT_PRINT_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_text_print, (uint8_t* data, uint32_t data_size));
#endif
#ifndef OCALL_LSTAT_DEFINED__
#define OCALL_LSTAT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_lstat, (const char* path, struct stat* buf, size_t size));
#endif
#ifndef OCALL_STAT_DEFINED__
#define OCALL_STAT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_stat, (const char* path, struct stat* buf, size_t size));
#endif
#ifndef OCALL_FSTAT_DEFINED__
#define OCALL_FSTAT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fstat, (int fd, struct stat* buf, size_t size));
#endif
#ifndef OCALL_FTRUNCATE_DEFINED__
#define OCALL_FTRUNCATE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_ftruncate, (int fd, off_t length));
#endif
#ifndef OCALL_GETCWD_DEFINED__
#define OCALL_GETCWD_DEFINED__
char* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getcwd, (char* buf, size_t size));
#endif
#ifndef OCALL_GETPID_DEFINED__
#define OCALL_GETPID_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getpid, (void));
#endif
#ifndef OCALL_GETUID_DEFINED__
#define OCALL_GETUID_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getuid, (void));
#endif
#ifndef OCALL_GETENV_DEFINED__
#define OCALL_GETENV_DEFINED__
char* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getenv, (const char* name));
#endif
#ifndef OCALL_OPEN64_DEFINED__
#define OCALL_OPEN64_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_open64, (const char* filename, int flags, mode_t mode));
#endif
#ifndef OCALL_CLOSE_DEFINED__
#define OCALL_CLOSE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_close, (int fd));
#endif
#ifndef OCALL_LSEEK64_DEFINED__
#define OCALL_LSEEK64_DEFINED__
off_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_lseek64, (int fd, off_t offset, int whence));
#endif
#ifndef OCALL_READ_DEFINED__
#define OCALL_READ_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_read, (int fd, void* buf, size_t count));
#endif
#ifndef OCALL_WRITE_DEFINED__
#define OCALL_WRITE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_write, (int fd, const void* buf, size_t count));
#endif
#ifndef OCALL_FSYNC_DEFINED__
#define OCALL_FSYNC_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fsync, (int fd));
#endif
#ifndef OCALL_FCNTL_DEFINED__
#define OCALL_FCNTL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fcntl, (int fd, int cmd, void* arg, size_t size));
#endif
#ifndef OCALL_FCNTL64_DEFINED__
#define OCALL_FCNTL64_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fcntl64, (int fd, int cmd, void* arg, size_t size));
#endif
#ifndef OCALL_UNLINK_DEFINED__
#define OCALL_UNLINK_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_unlink, (const char* pathname));
#endif

sgx_status_t ecall_insert_matrix_card(sgx_enclave_id_t eid, uint8_t* data, uint32_t data_size);
sgx_status_t ecall_opendb(sgx_enclave_id_t eid, const char* db_name);
sgx_status_t ecall_execute_sql(sgx_enclave_id_t eid, const char* sql);
sgx_status_t ecall_get_text_size(sgx_enclave_id_t eid, const char* sql, int* size);
sgx_status_t ecall_get_text_value(sgx_enclave_id_t eid, const char* sql, uint8_t* data_from_db, uint32_t data_from_db_size);
sgx_status_t ecall_close_db(sgx_enclave_id_t eid);
sgx_status_t ecall_get_current_stored_value(sgx_enclave_id_t eid, uint8_t* result);
sgx_status_t generate_matrix_card_values(sgx_enclave_id_t eid, int* retval, uint8_t* array, size_t array_size);
sgx_status_t get_sealed_data_size(sgx_enclave_id_t eid, uint32_t* retval, uint32_t fsize);
sgx_status_t seal_data(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* plaintext, size_t plaintext_size, uint8_t* sealed_data, size_t sealed_size);
sgx_status_t unseal_data(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* sealed_data, size_t sealed_size, uint8_t* plaintext, size_t plaintext_size);
sgx_status_t ecall_validate_coords(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t client_id, Coords* coords, uint8_t num_coords, uint8_t* result);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
