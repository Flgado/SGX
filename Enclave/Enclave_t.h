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

int generate_matrix_card_values(uint32_t client_id, uint8_t* array, size_t array_size);
sgx_status_t ecall_validate_coords(uint32_t client_id, Coords* coords, size_t num_coords, uint8_t* result, uint64_t timestamp);

sgx_status_t SGX_CDECL ocall_write_sealed_data(int* retval, int client_id, uint8_t* sealed_data, size_t sealed_data_size);
sgx_status_t SGX_CDECL ocall_get_sealed_data_size(int* retval, int client_id, size_t* file_size);
sgx_status_t SGX_CDECL ocall_read_sealed_data(int* retval, int client_id, uint8_t* data, size_t data_size);
sgx_status_t SGX_CDECL ocall_print(const char* str);
sgx_status_t SGX_CDECL ocall_println_string(const char* str);
sgx_status_t SGX_CDECL ocall_print_string(const char* str);
sgx_status_t SGX_CDECL ocall_print_error(const char* str);
sgx_status_t SGX_CDECL ocall_text_print(uint8_t* data, uint32_t data_size);
sgx_status_t SGX_CDECL ocall_copy_file(const char* src_path, const char* dest_path);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
