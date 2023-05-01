#include "Enclave_t.h"
#include "sgx_trts.h"
#include <stdlib.h>
#include <stdio.h>

int generate_random_array(int* array, size_t array_size) {
    ocall_print("Processing random array generation...");
    sgx_status_t status;

    for (int i = 0; i < array_size; i++) {
	uint16_t rand_num;
        status = sgx_read_rand((unsigned char*)&rand_num, sizeof(int));
        if (status != SGX_SUCCESS) {
            ocall_print("Error generating random number");
            return SGX_ERROR_UNEXPECTED;
        }
	array[i] = rand_num % 1000 + 1;
    }

    return SGX_SUCCESS;
}
