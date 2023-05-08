#include <stdio.h>
#include <iostream>
#include <iomanip>
#include <string>
#include "Enclave_u.h"
#include "sgx_urts.h"
#include "sgx_utils/sgx_utils.h"

#define MATRIX_CARD_SIZE 64
#define ENCLAVE_FILE "Enclave.signed.so"

sgx_enclave_id_t global_eid = 0;

// OCall implementations
void ocall_print(const char* str) {
    printf("%s\n", str);
}

void ocall_print_error(const char *str) {
    std::cerr << str << std::endl;
}

void ocall_print_string(const char *str){
    std::cout << str;
}

void ocall_println_string(const char *str){
    std::cout << str << std::endl;
}

void bootstrap_persistence() {
    ecall_opendb(global_eid, "matrix_cards.db");
    const char *card_table_create_query = 
        "CREATE TABLE IF NOT EXISTS card (\
            id INTEGER PRIMARY KEY AUTOINCREMENT, \
            matrix_data BLOB NOT NULL \
        );";

    ecall_execute_sql(global_eid, card_table_create_query);
}

void pretty_print_arr(const uint8_t *data, size_t size, size_t max_per_line) {
    for (size_t i = 0; i < size; ++i) {
        std::cout << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(data[i]) << ' ';
        
        if ((i + 1) % max_per_line == 0) {
            std::cout << std::endl;
        }
    }
    std::cout << std::dec << std::endl;
}

void ocall_text_print(uint8_t *data, uint32_t data_size) {
    for(int i = 0;i < data_size;i++) {
        std::cout << data[i];
    }
    return;
}

int main(int argc, char const *argv[]) {
    ocall_println_string("[-] enclave::starting...");

    int ret;	
    if (initialize_enclave(&global_eid, "enclave.token", "enclave.signed.so") < 0) {
        std::cout << "Fail to initialize enclave." << std::endl;
        return 1;
    }

    ocall_println_string("[-] enclave::generate_matrix_card_values\n");

    // Generate random array
    uint8_t *array = (uint8_t*) malloc(MATRIX_CARD_SIZE * sizeof(uint8_t));
    sgx_status_t status = generate_matrix_card_values(global_eid, &ret, array, MATRIX_CARD_SIZE);
    if (status != SGX_SUCCESS) {
	printf("Error: %s\n", strerror(status));
        return 1;
    }

    ocall_println_string("[-] enclave::generated_matrix");
    pretty_print_arr(array, MATRIX_CARD_SIZE, 8);


    ocall_println_string("\n[-] enclave::sealing");

    bootstrap_persistence();

    uint32_t arr_size = sizeof(uint8_t) * MATRIX_CARD_SIZE;
    uint32_t sealed_data_size = 0;
    ret = get_sealed_data_size(global_eid, &sealed_data_size, arr_size);
    if (ret != SGX_SUCCESS) {
        return -1;
    }

    // Seal the array
    uint8_t *sealed_data_buf = new uint8_t[sealed_data_size];

    sgx_status_t retval;
    ret = seal_data(global_eid, &retval, array, arr_size, sealed_data_buf, sealed_data_size);

    if (ret != SGX_SUCCESS) {
        ocall_println_string("error");
        free(sealed_data_buf);
        return -1;
    }
    else if (retval != SGX_SUCCESS) {
        ocall_println_string("error 2");
        free(sealed_data_buf);
        return -1;
    }

    ocall_println_string("\n[-] enclave::sealed");
    ecall_insert_matrix_card(global_eid, sealed_data_buf, sealed_data_size);

    const char *query = "SELECT matrix_data FROM card ORDER BY id DESC LIMIT 1;";
    int size = 0;

    ecall_get_text_size(global_eid, query, &size);
    printf("[-] enclave::ecall_get_text_size() = %d\n", size);

    uint8_t *sealed_from_db = new uint8_t[size];
    ecall_get_text_value(global_eid, query, sealed_from_db, size);

    ocall_println_string("\n[-] enclave::seal_from_db");
    pretty_print_arr(sealed_from_db, size, 50);

    ocall_println_string("[-] enclave::unsealing");

    uint8_t *unsealed = new uint8_t[64];
    uint32_t unsealed_sz = 64;

    //ret = unseal_data(global_eid, &retval, sealed_data_buf, sealed_data_size, unsealed, unsealed_sz);
    ret = unseal_data(global_eid, &retval, sealed_from_db, size, unsealed, unsealed_sz);

    if (ret != SGX_SUCCESS) {
        ocall_println_string("error");
        free(sealed_from_db);
        return -1;
    }
    else if (retval != SGX_SUCCESS) {
        ocall_println_string("error 2");
        free(sealed_from_db);
        return -1;
    }

    ocall_println_string("[-] enclave::unsealed");
    pretty_print_arr(unsealed, unsealed_sz, 8);

    return 0;
}
