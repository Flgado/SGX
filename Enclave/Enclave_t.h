#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

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

void ecall_insert_matrix_card(uint8_t* data, uint32_t data_size);
void ecall_opendb(const char* db_name);
void ecall_execute_sql(const char* sql);
void ecall_get_text_size(const char* sql, int* size);
void ecall_get_text_value(const char* sql, uint8_t* data_from_db, uint32_t data_from_db_size);
void ecall_close_db(void);
void ecall_get_current_stored_value(uint8_t* result);
int generate_matrix_card_values(uint8_t* array, size_t array_size);
uint32_t get_sealed_data_size(uint32_t fsize);
sgx_status_t seal_data(uint8_t* plaintext, size_t plaintext_size, uint8_t* sealed_data, size_t sealed_size);
sgx_status_t unseal_data(uint8_t* sealed_data, size_t sealed_size, uint8_t* plaintext, size_t plaintext_size);
sgx_status_t ecall_validate_coords(uint32_t client_id, Coords* coords, uint8_t num_coords, uint8_t* result);

sgx_status_t SGX_CDECL ocall_print(const char* str);
sgx_status_t SGX_CDECL ocall_println_string(const char* str);
sgx_status_t SGX_CDECL ocall_print_string(const char* str);
sgx_status_t SGX_CDECL ocall_print_error(const char* str);
sgx_status_t SGX_CDECL ocall_text_print(uint8_t* data, uint32_t data_size);
sgx_status_t SGX_CDECL ocall_lstat(int* retval, const char* path, struct stat* buf, size_t size);
sgx_status_t SGX_CDECL ocall_stat(int* retval, const char* path, struct stat* buf, size_t size);
sgx_status_t SGX_CDECL ocall_fstat(int* retval, int fd, struct stat* buf, size_t size);
sgx_status_t SGX_CDECL ocall_ftruncate(int* retval, int fd, off_t length);
sgx_status_t SGX_CDECL ocall_getcwd(char** retval, char* buf, size_t size);
sgx_status_t SGX_CDECL ocall_getpid(int* retval);
sgx_status_t SGX_CDECL ocall_getuid(int* retval);
sgx_status_t SGX_CDECL ocall_getenv(char** retval, const char* name);
sgx_status_t SGX_CDECL ocall_open64(int* retval, const char* filename, int flags, mode_t mode);
sgx_status_t SGX_CDECL ocall_close(int* retval, int fd);
sgx_status_t SGX_CDECL ocall_lseek64(off_t* retval, int fd, off_t offset, int whence);
sgx_status_t SGX_CDECL ocall_read(int* retval, int fd, void* buf, size_t count);
sgx_status_t SGX_CDECL ocall_write(int* retval, int fd, const void* buf, size_t count);
sgx_status_t SGX_CDECL ocall_fsync(int* retval, int fd);
sgx_status_t SGX_CDECL ocall_fcntl(int* retval, int fd, int cmd, void* arg, size_t size);
sgx_status_t SGX_CDECL ocall_fcntl64(int* retval, int fd, int cmd, void* arg, size_t size);
sgx_status_t SGX_CDECL ocall_unlink(int* retval, const char* pathname);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
