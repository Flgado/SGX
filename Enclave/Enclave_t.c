#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

typedef struct ms_ecall_get_enclave_version_t {
	sgx_status_t ms_retval;
	uint8_t* ms_version;
} ms_ecall_get_enclave_version_t;

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

static sgx_status_t SGX_CDECL sgx_ecall_setup_card(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_setup_card_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_setup_card_t* ms = SGX_CAST(ms_ecall_setup_card_t*, pms);
	ms_ecall_setup_card_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_setup_card_t), ms, sizeof(ms_ecall_setup_card_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_array = __in_ms.ms_array;
	size_t _tmp_array_size = __in_ms.ms_array_size;
	size_t _len_array = _tmp_array_size;
	uint8_t* _in_array = NULL;
	int _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_array, _len_array);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_array != NULL && _len_array != 0) {
		if ( _len_array % sizeof(*_tmp_array) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_array = (uint8_t*)malloc(_len_array);
		if (_in_array == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_array, _len_array, _tmp_array, _len_array)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	_in_retval = ecall_setup_card(__in_ms.ms_client_id, _in_array, _tmp_array_size);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_array) {
		if (memcpy_verw_s(_tmp_array, _len_array, _in_array, _len_array)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_array) free(_in_array);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_validate_coords(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_validate_coords_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_validate_coords_t* ms = SGX_CAST(ms_ecall_validate_coords_t*, pms);
	ms_ecall_validate_coords_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_validate_coords_t), ms, sizeof(ms_ecall_validate_coords_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	Coords* _tmp_coords = __in_ms.ms_coords;
	size_t _tmp_num_coords = __in_ms.ms_num_coords;
	size_t _len_coords = _tmp_num_coords * sizeof(Coords);
	Coords* _in_coords = NULL;
	uint8_t* _tmp_result = __in_ms.ms_result;
	size_t _len_result = sizeof(uint8_t);
	uint8_t* _in_result = NULL;
	sgx_status_t _in_retval;

	if (sizeof(*_tmp_coords) != 0 &&
		(size_t)_tmp_num_coords > (SIZE_MAX / sizeof(*_tmp_coords))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_coords, _len_coords);
	CHECK_UNIQUE_POINTER(_tmp_result, _len_result);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_coords != NULL && _len_coords != 0) {
		_in_coords = (Coords*)malloc(_len_coords);
		if (_in_coords == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_coords, _len_coords, _tmp_coords, _len_coords)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_result != NULL && _len_result != 0) {
		if ( _len_result % sizeof(*_tmp_result) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_result = (uint8_t*)malloc(_len_result)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_result, 0, _len_result);
	}
	_in_retval = ecall_validate_coords(__in_ms.ms_client_id, _in_coords, _tmp_num_coords, _in_result, __in_ms.ms_timestamp);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_result) {
		if (memcpy_verw_s(_tmp_result, _len_result, _in_result, _len_result)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_coords) free(_in_coords);
	if (_in_result) free(_in_result);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_print_logs(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_print_logs_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_print_logs_t* ms = SGX_CAST(ms_ecall_print_logs_t*, pms);
	ms_ecall_print_logs_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_print_logs_t), ms, sizeof(ms_ecall_print_logs_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_enc_client_id = __in_ms.ms_enc_client_id;
	int _tmp_enc_sz = __in_ms.ms_enc_sz;
	size_t _len_enc_client_id = _tmp_enc_sz;
	uint8_t* _in_enc_client_id = NULL;
	uint8_t* _tmp_tag = __in_ms.ms_tag;
	size_t _len_tag = 16;
	uint8_t* _in_tag = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_enc_client_id, _len_enc_client_id);
	CHECK_UNIQUE_POINTER(_tmp_tag, _len_tag);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_enc_client_id != NULL && _len_enc_client_id != 0) {
		if ( _len_enc_client_id % sizeof(*_tmp_enc_client_id) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_enc_client_id = (uint8_t*)malloc(_len_enc_client_id);
		if (_in_enc_client_id == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_enc_client_id, _len_enc_client_id, _tmp_enc_client_id, _len_enc_client_id)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_tag != NULL && _len_tag != 0) {
		if ( _len_tag % sizeof(*_tmp_tag) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_tag = (uint8_t*)malloc(_len_tag);
		if (_in_tag == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_tag, _len_tag, _tmp_tag, _len_tag)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	_in_retval = ecall_print_logs(_in_enc_client_id, _tmp_enc_sz, _in_tag);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	if (_in_enc_client_id) free(_in_enc_client_id);
	if (_in_tag) free(_in_tag);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_generate_key(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_generate_key_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_generate_key_t* ms = SGX_CAST(ms_ecall_generate_key_t*, pms);
	ms_ecall_generate_key_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_generate_key_t), ms, sizeof(ms_ecall_generate_key_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_key = __in_ms.ms_key;
	size_t _tmp_key_size = __in_ms.ms_key_size;
	size_t _len_key = _tmp_key_size;
	uint8_t* _in_key = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_key, _len_key);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_key != NULL && _len_key != 0) {
		if ( _len_key % sizeof(*_tmp_key) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_key = (uint8_t*)malloc(_len_key)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_key, 0, _len_key);
	}
	_in_retval = ecall_generate_key(_in_key, _tmp_key_size);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_key) {
		if (memcpy_verw_s(_tmp_key, _len_key, _in_key, _len_key)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_key) free(_in_key);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_migration_finalize(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_migration_finalize_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_migration_finalize_t* ms = SGX_CAST(ms_ecall_migration_finalize_t*, pms);
	ms_ecall_migration_finalize_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_migration_finalize_t), ms, sizeof(ms_ecall_migration_finalize_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_encrypted = __in_ms.ms_encrypted;
	size_t _tmp_encrypted_sz = __in_ms.ms_encrypted_sz;
	size_t _len_encrypted = _tmp_encrypted_sz;
	uint8_t* _in_encrypted = NULL;
	uint8_t* _tmp_mac = __in_ms.ms_mac;
	size_t _tmp_mac_sz = __in_ms.ms_mac_sz;
	size_t _len_mac = _tmp_mac_sz;
	uint8_t* _in_mac = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_encrypted, _len_encrypted);
	CHECK_UNIQUE_POINTER(_tmp_mac, _len_mac);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_encrypted != NULL && _len_encrypted != 0) {
		if ( _len_encrypted % sizeof(*_tmp_encrypted) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_encrypted = (uint8_t*)malloc(_len_encrypted);
		if (_in_encrypted == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_encrypted, _len_encrypted, _tmp_encrypted, _len_encrypted)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_mac != NULL && _len_mac != 0) {
		if ( _len_mac % sizeof(*_tmp_mac) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_mac = (uint8_t*)malloc(_len_mac);
		if (_in_mac == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_mac, _len_mac, _tmp_mac, _len_mac)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	_in_retval = ecall_migration_finalize(_in_encrypted, _tmp_encrypted_sz, _in_mac, _tmp_mac_sz);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	if (_in_encrypted) free(_in_encrypted);
	if (_in_mac) free(_in_mac);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_migration_prepare_record(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_migration_prepare_record_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_migration_prepare_record_t* ms = SGX_CAST(ms_ecall_migration_prepare_record_t*, pms);
	ms_ecall_migration_prepare_record_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_migration_prepare_record_t), ms, sizeof(ms_ecall_migration_prepare_record_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint8_t** _tmp_encrypted = __in_ms.ms_encrypted;
	size_t _len_encrypted = sizeof(uint8_t*);
	uint8_t** _in_encrypted = NULL;
	size_t* _tmp_encrypted_sz = __in_ms.ms_encrypted_sz;
	size_t _len_encrypted_sz = sizeof(size_t);
	size_t* _in_encrypted_sz = NULL;
	sgx_aes_gcm_128bit_tag_t** _tmp_out_mac = __in_ms.ms_out_mac;
	size_t _len_out_mac = sizeof(sgx_aes_gcm_128bit_tag_t*);
	sgx_aes_gcm_128bit_tag_t** _in_out_mac = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_encrypted, _len_encrypted);
	CHECK_UNIQUE_POINTER(_tmp_encrypted_sz, _len_encrypted_sz);
	CHECK_UNIQUE_POINTER(_tmp_out_mac, _len_out_mac);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_encrypted != NULL && _len_encrypted != 0) {
		if ( _len_encrypted % sizeof(*_tmp_encrypted) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_encrypted = (uint8_t**)malloc(_len_encrypted)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_encrypted, 0, _len_encrypted);
	}
	if (_tmp_encrypted_sz != NULL && _len_encrypted_sz != 0) {
		if ( _len_encrypted_sz % sizeof(*_tmp_encrypted_sz) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_encrypted_sz = (size_t*)malloc(_len_encrypted_sz)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_encrypted_sz, 0, _len_encrypted_sz);
	}
	if (_tmp_out_mac != NULL && _len_out_mac != 0) {
		if ( _len_out_mac % sizeof(*_tmp_out_mac) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_out_mac = (sgx_aes_gcm_128bit_tag_t**)malloc(_len_out_mac)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_out_mac, 0, _len_out_mac);
	}
	_in_retval = ecall_migration_prepare_record(__in_ms.ms_client_id, _in_encrypted, _in_encrypted_sz, _in_out_mac);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_encrypted) {
		if (memcpy_verw_s(_tmp_encrypted, _len_encrypted, _in_encrypted, _len_encrypted)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_encrypted_sz) {
		if (memcpy_verw_s(_tmp_encrypted_sz, _len_encrypted_sz, _in_encrypted_sz, _len_encrypted_sz)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_out_mac) {
		if (memcpy_verw_s(_tmp_out_mac, _len_out_mac, _in_out_mac, _len_out_mac)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_encrypted) free(_in_encrypted);
	if (_in_encrypted_sz) free(_in_encrypted_sz);
	if (_in_out_mac) free(_in_out_mac);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_get_enclave_version(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_get_enclave_version_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_get_enclave_version_t* ms = SGX_CAST(ms_ecall_get_enclave_version_t*, pms);
	ms_ecall_get_enclave_version_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_get_enclave_version_t), ms, sizeof(ms_ecall_get_enclave_version_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_version = __in_ms.ms_version;
	size_t _len_version = sizeof(uint8_t);
	uint8_t* _in_version = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_version, _len_version);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_version != NULL && _len_version != 0) {
		if ( _len_version % sizeof(*_tmp_version) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_version = (uint8_t*)malloc(_len_version)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_version, 0, _len_version);
	}
	_in_retval = ecall_get_enclave_version(_in_version);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_version) {
		if (memcpy_verw_s(_tmp_version, _len_version, _in_version, _len_version)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_version) free(_in_version);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_init_session_initiator(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_init_session_initiator_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_init_session_initiator_t* ms = SGX_CAST(ms_ecall_init_session_initiator_t*, pms);
	ms_ecall_init_session_initiator_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_init_session_initiator_t), ms, sizeof(ms_ecall_init_session_initiator_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	sgx_status_t* _tmp_dh_status = __in_ms.ms_dh_status;
	size_t _len_dh_status = sizeof(sgx_status_t);
	sgx_status_t* _in_dh_status = NULL;

	CHECK_UNIQUE_POINTER(_tmp_dh_status, _len_dh_status);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_dh_status != NULL && _len_dh_status != 0) {
		if ((_in_dh_status = (sgx_status_t*)malloc(_len_dh_status)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_dh_status, 0, _len_dh_status);
	}
	ecall_init_session_initiator(_in_dh_status);
	if (_in_dh_status) {
		if (memcpy_verw_s(_tmp_dh_status, _len_dh_status, _in_dh_status, _len_dh_status)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_dh_status) free(_in_dh_status);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_init_session_responder(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_init_session_responder_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_init_session_responder_t* ms = SGX_CAST(ms_ecall_init_session_responder_t*, pms);
	ms_ecall_init_session_responder_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_init_session_responder_t), ms, sizeof(ms_ecall_init_session_responder_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	sgx_status_t* _tmp_dh_status = __in_ms.ms_dh_status;
	size_t _len_dh_status = sizeof(sgx_status_t);
	sgx_status_t* _in_dh_status = NULL;

	CHECK_UNIQUE_POINTER(_tmp_dh_status, _len_dh_status);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_dh_status != NULL && _len_dh_status != 0) {
		if ((_in_dh_status = (sgx_status_t*)malloc(_len_dh_status)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_dh_status, 0, _len_dh_status);
	}
	ecall_init_session_responder(_in_dh_status);
	if (_in_dh_status) {
		if (memcpy_verw_s(_tmp_dh_status, _len_dh_status, _in_dh_status, _len_dh_status)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_dh_status) free(_in_dh_status);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_create_message1(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_create_message1_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_create_message1_t* ms = SGX_CAST(ms_ecall_create_message1_t*, pms);
	ms_ecall_create_message1_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_create_message1_t), ms, sizeof(ms_ecall_create_message1_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	sgx_dh_msg1_t* _tmp_msg1 = __in_ms.ms_msg1;
	size_t _len_msg1 = sizeof(sgx_dh_msg1_t);
	sgx_dh_msg1_t* _in_msg1 = NULL;
	sgx_status_t* _tmp_dh_status = __in_ms.ms_dh_status;
	size_t _len_dh_status = sizeof(sgx_status_t);
	sgx_status_t* _in_dh_status = NULL;

	CHECK_UNIQUE_POINTER(_tmp_msg1, _len_msg1);
	CHECK_UNIQUE_POINTER(_tmp_dh_status, _len_dh_status);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_msg1 != NULL && _len_msg1 != 0) {
		if ((_in_msg1 = (sgx_dh_msg1_t*)malloc(_len_msg1)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_msg1, 0, _len_msg1);
	}
	if (_tmp_dh_status != NULL && _len_dh_status != 0) {
		if ((_in_dh_status = (sgx_status_t*)malloc(_len_dh_status)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_dh_status, 0, _len_dh_status);
	}
	ecall_create_message1(_in_msg1, _in_dh_status);
	if (_in_msg1) {
		if (memcpy_verw_s(_tmp_msg1, _len_msg1, _in_msg1, _len_msg1)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_dh_status) {
		if (memcpy_verw_s(_tmp_dh_status, _len_dh_status, _in_dh_status, _len_dh_status)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_msg1) free(_in_msg1);
	if (_in_dh_status) free(_in_dh_status);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_process_message1(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_process_message1_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_process_message1_t* ms = SGX_CAST(ms_ecall_process_message1_t*, pms);
	ms_ecall_process_message1_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_process_message1_t), ms, sizeof(ms_ecall_process_message1_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const sgx_dh_msg1_t* _tmp_msg1 = __in_ms.ms_msg1;
	size_t _len_msg1 = sizeof(sgx_dh_msg1_t);
	sgx_dh_msg1_t* _in_msg1 = NULL;
	sgx_dh_msg2_t* _tmp_msg2 = __in_ms.ms_msg2;
	size_t _len_msg2 = sizeof(sgx_dh_msg2_t);
	sgx_dh_msg2_t* _in_msg2 = NULL;
	sgx_status_t* _tmp_dh_status = __in_ms.ms_dh_status;
	size_t _len_dh_status = sizeof(sgx_status_t);
	sgx_status_t* _in_dh_status = NULL;

	CHECK_UNIQUE_POINTER(_tmp_msg1, _len_msg1);
	CHECK_UNIQUE_POINTER(_tmp_msg2, _len_msg2);
	CHECK_UNIQUE_POINTER(_tmp_dh_status, _len_dh_status);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_msg1 != NULL && _len_msg1 != 0) {
		_in_msg1 = (sgx_dh_msg1_t*)malloc(_len_msg1);
		if (_in_msg1 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_msg1, _len_msg1, _tmp_msg1, _len_msg1)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_msg2 != NULL && _len_msg2 != 0) {
		if ((_in_msg2 = (sgx_dh_msg2_t*)malloc(_len_msg2)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_msg2, 0, _len_msg2);
	}
	if (_tmp_dh_status != NULL && _len_dh_status != 0) {
		if ((_in_dh_status = (sgx_status_t*)malloc(_len_dh_status)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_dh_status, 0, _len_dh_status);
	}
	ecall_process_message1((const sgx_dh_msg1_t*)_in_msg1, _in_msg2, _in_dh_status);
	if (_in_msg2) {
		if (memcpy_verw_s(_tmp_msg2, _len_msg2, _in_msg2, _len_msg2)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_dh_status) {
		if (memcpy_verw_s(_tmp_dh_status, _len_dh_status, _in_dh_status, _len_dh_status)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_msg1) free(_in_msg1);
	if (_in_msg2) free(_in_msg2);
	if (_in_dh_status) free(_in_dh_status);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_process_message2(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_process_message2_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_process_message2_t* ms = SGX_CAST(ms_ecall_process_message2_t*, pms);
	ms_ecall_process_message2_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_process_message2_t), ms, sizeof(ms_ecall_process_message2_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const sgx_dh_msg2_t* _tmp_msg2 = __in_ms.ms_msg2;
	size_t _len_msg2 = sizeof(sgx_dh_msg2_t);
	sgx_dh_msg2_t* _in_msg2 = NULL;
	sgx_dh_msg3_t* _tmp_msg3 = __in_ms.ms_msg3;
	size_t _len_msg3 = sizeof(sgx_dh_msg3_t);
	sgx_dh_msg3_t* _in_msg3 = NULL;
	sgx_status_t* _tmp_dh_status = __in_ms.ms_dh_status;
	size_t _len_dh_status = sizeof(sgx_status_t);
	sgx_status_t* _in_dh_status = NULL;

	CHECK_UNIQUE_POINTER(_tmp_msg2, _len_msg2);
	CHECK_UNIQUE_POINTER(_tmp_msg3, _len_msg3);
	CHECK_UNIQUE_POINTER(_tmp_dh_status, _len_dh_status);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_msg2 != NULL && _len_msg2 != 0) {
		_in_msg2 = (sgx_dh_msg2_t*)malloc(_len_msg2);
		if (_in_msg2 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_msg2, _len_msg2, _tmp_msg2, _len_msg2)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_msg3 != NULL && _len_msg3 != 0) {
		if ((_in_msg3 = (sgx_dh_msg3_t*)malloc(_len_msg3)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_msg3, 0, _len_msg3);
	}
	if (_tmp_dh_status != NULL && _len_dh_status != 0) {
		if ((_in_dh_status = (sgx_status_t*)malloc(_len_dh_status)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_dh_status, 0, _len_dh_status);
	}
	ecall_process_message2((const sgx_dh_msg2_t*)_in_msg2, _in_msg3, _in_dh_status);
	if (_in_msg3) {
		if (memcpy_verw_s(_tmp_msg3, _len_msg3, _in_msg3, _len_msg3)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_dh_status) {
		if (memcpy_verw_s(_tmp_dh_status, _len_dh_status, _in_dh_status, _len_dh_status)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_msg2) free(_in_msg2);
	if (_in_msg3) free(_in_msg3);
	if (_in_dh_status) free(_in_dh_status);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_process_message3(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_process_message3_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_process_message3_t* ms = SGX_CAST(ms_ecall_process_message3_t*, pms);
	ms_ecall_process_message3_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_process_message3_t), ms, sizeof(ms_ecall_process_message3_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const sgx_dh_msg3_t* _tmp_msg3 = __in_ms.ms_msg3;
	size_t _len_msg3 = sizeof(sgx_dh_msg3_t);
	sgx_dh_msg3_t* _in_msg3 = NULL;
	sgx_status_t* _tmp_dh_status = __in_ms.ms_dh_status;
	size_t _len_dh_status = sizeof(sgx_status_t);
	sgx_status_t* _in_dh_status = NULL;

	CHECK_UNIQUE_POINTER(_tmp_msg3, _len_msg3);
	CHECK_UNIQUE_POINTER(_tmp_dh_status, _len_dh_status);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_msg3 != NULL && _len_msg3 != 0) {
		_in_msg3 = (sgx_dh_msg3_t*)malloc(_len_msg3);
		if (_in_msg3 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_msg3, _len_msg3, _tmp_msg3, _len_msg3)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_dh_status != NULL && _len_dh_status != 0) {
		if ((_in_dh_status = (sgx_status_t*)malloc(_len_dh_status)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_dh_status, 0, _len_dh_status);
	}
	ecall_process_message3((const sgx_dh_msg3_t*)_in_msg3, _in_dh_status);
	if (_in_dh_status) {
		if (memcpy_verw_s(_tmp_dh_status, _len_dh_status, _in_dh_status, _len_dh_status)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_msg3) free(_in_msg3);
	if (_in_dh_status) free(_in_dh_status);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[13];
} g_ecall_table = {
	13,
	{
		{(void*)(uintptr_t)sgx_ecall_setup_card, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_validate_coords, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_print_logs, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_generate_key, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_migration_finalize, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_migration_prepare_record, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_get_enclave_version, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_init_session_initiator, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_init_session_responder, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_create_message1, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_process_message1, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_process_message2, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_process_message3, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[4][13];
} g_dyn_entry_table = {
	4,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_write_sealed_data(int* retval, int client_id, uint8_t* sealed_data, size_t sealed_data_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_sealed_data = sealed_data_size;

	ms_ocall_write_sealed_data_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_write_sealed_data_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(sealed_data, _len_sealed_data);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (sealed_data != NULL) ? _len_sealed_data : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_write_sealed_data_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_write_sealed_data_t));
	ocalloc_size -= sizeof(ms_ocall_write_sealed_data_t);

	if (memcpy_verw_s(&ms->ms_client_id, sizeof(ms->ms_client_id), &client_id, sizeof(client_id))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (sealed_data != NULL) {
		if (memcpy_verw_s(&ms->ms_sealed_data, sizeof(uint8_t*), &__tmp, sizeof(uint8_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_sealed_data % sizeof(*sealed_data) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, sealed_data, _len_sealed_data)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_sealed_data);
		ocalloc_size -= _len_sealed_data;
	} else {
		ms->ms_sealed_data = NULL;
	}

	if (memcpy_verw_s(&ms->ms_sealed_data_size, sizeof(ms->ms_sealed_data_size), &sealed_data_size, sizeof(sealed_data_size))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_get_sealed_data_size(int* retval, int client_id, size_t* file_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_file_size = sizeof(size_t);

	ms_ocall_get_sealed_data_size_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_get_sealed_data_size_t);
	void *__tmp = NULL;

	void *__tmp_file_size = NULL;

	CHECK_ENCLAVE_POINTER(file_size, _len_file_size);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (file_size != NULL) ? _len_file_size : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_get_sealed_data_size_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_get_sealed_data_size_t));
	ocalloc_size -= sizeof(ms_ocall_get_sealed_data_size_t);

	if (memcpy_verw_s(&ms->ms_client_id, sizeof(ms->ms_client_id), &client_id, sizeof(client_id))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (file_size != NULL) {
		if (memcpy_verw_s(&ms->ms_file_size, sizeof(size_t*), &__tmp, sizeof(size_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_file_size = __tmp;
		if (_len_file_size % sizeof(*file_size) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_file_size, 0, _len_file_size);
		__tmp = (void *)((size_t)__tmp + _len_file_size);
		ocalloc_size -= _len_file_size;
	} else {
		ms->ms_file_size = NULL;
	}

	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (file_size) {
			if (memcpy_s((void*)file_size, _len_file_size, __tmp_file_size, _len_file_size)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_read_sealed_data(int* retval, int client_id, uint8_t* data, size_t data_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_data = data_size;

	ms_ocall_read_sealed_data_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_read_sealed_data_t);
	void *__tmp = NULL;

	void *__tmp_data = NULL;

	CHECK_ENCLAVE_POINTER(data, _len_data);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (data != NULL) ? _len_data : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_read_sealed_data_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_read_sealed_data_t));
	ocalloc_size -= sizeof(ms_ocall_read_sealed_data_t);

	if (memcpy_verw_s(&ms->ms_client_id, sizeof(ms->ms_client_id), &client_id, sizeof(client_id))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (data != NULL) {
		if (memcpy_verw_s(&ms->ms_data, sizeof(uint8_t*), &__tmp, sizeof(uint8_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_data = __tmp;
		if (_len_data % sizeof(*data) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_data, 0, _len_data);
		__tmp = (void *)((size_t)__tmp + _len_data);
		ocalloc_size -= _len_data;
	} else {
		ms->ms_data = NULL;
	}

	if (memcpy_verw_s(&ms->ms_data_size, sizeof(ms->ms_data_size), &data_size, sizeof(data_size))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (data) {
			if (memcpy_s((void*)data, _len_data, __tmp_data, _len_data)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_print(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_t));
	ocalloc_size -= sizeof(ms_ocall_print_t);

	if (str != NULL) {
		if (memcpy_verw_s(&ms->ms_str, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}

	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

