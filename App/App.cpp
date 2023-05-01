#include <stdio.h>
#include "Enclave_u.h"
#include "sgx_urts.h"
#include "sgx_utils/sgx_utils.h"
#include "iofiles_utils/iofiles_utils.h"

#define ARRAY_SIZE 64

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

// OCall implementations
void ocall_print(const char* str) {
    printf("%s\n", str);
}

int main(int argc, char const *argv[]) {
	
    int ret;	
    if (initialize_enclave(&global_eid, "enclave.token", "enclave.signed.so") < 0) {
        std::cout << "Fail to initialize enclave." << std::endl;
        return 1;
    }

    // Generate random array
    int array[ARRAY_SIZE];
    sgx_status_t status = generate_random_array(global_eid, &ret, array, ARRAY_SIZE);
    if (status != SGX_SUCCESS) {
	printf("Error: %s\n", strerror(status));
        return 1;
    }

    for(int i = 0; i<ARRAY_SIZE; i++){
	    printf("array %d\n", array[i]);
    }
    // Seal the array
    size_t sealed_size = sizeof(sgx_sealed_data_t) + sizeof(array);
    uint8_t* sealed_data = (uint8_t*)malloc(sealed_size);

    sgx_status_t ecall_status;
    status = seal(global_eid, &ecall_status,
            (uint8_t*)&array, sizeof(array),
   	    (sgx_sealed_data_t*)sealed_data, sealed_size);
    
    if (!is_ecall_successful(status, "Sealing failed :(", ecall_status)) {
        return 1;
    }


     //Write the sealed data with identifier 1 to file
    if (!write_seal_data(sealed_data, sealed_size, 1)) {
        return 1;
    }

    free(sealed_data);
    
    // Read the sealed data with identifier 1 from file
    uint8_t* read_sealed_data = (uint8_t*)malloc(sealed_size);
    if (!read_seal_data(1, read_sealed_data, sealed_size)) {
        return 1;
    }

    int unsealed_array[ARRAY_SIZE];
    // Unseal the array
    status = unseal(global_eid, &ecall_status,
            (sgx_sealed_data_t*)read_sealed_data, sealed_size,
   	    (uint8_t*)&unsealed_array, sizeof(unsealed_array));
    
    free(read_sealed_data);
    if (!is_ecall_successful(status, "Unsealing failed :(", ecall_status)) {
        return 1;
    }

    for(int i = 0; i < ARRAY_SIZE; i++){
	    printf("Unseled data: %d\n", unsealed_array[i]);
    }

    std::cout << "Seal round trip success! Receive back array of size " << ARRAY_SIZE << std::endl;

    return 0;
}
