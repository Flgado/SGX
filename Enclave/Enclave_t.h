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

int generate_matrix_card_values(uint8_t* array, size_t array_size);
sgx_status_t ecall_validate_coords(uint32_t client_id, Coords* coords, size_t num_coords, uint8_t* result, uint64_t timestamp);

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
sgx_status_t SGX_CDECL ocall_copy_file(const char* src_path, const char* dest_path);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
