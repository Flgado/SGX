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
#ifndef OCALL_COPY_FILE_DEFINED__
#define OCALL_COPY_FILE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_copy_file, (const char* src_path, const char* dest_path));
#endif

sgx_status_t generate_matrix_card_values(sgx_enclave_id_t eid, int* retval, uint32_t client_id, uint8_t* array, size_t array_size);
sgx_status_t ecall_validate_coords(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t client_id, Coords* coords, size_t num_coords, uint8_t* result, uint64_t timestamp);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
