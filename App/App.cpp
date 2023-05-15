#include <stdio.h>
#include <iostream>
#include <iomanip>
#include <string>
#include "Enclave_u.h"
#include "sgx_urts.h"
#include "sgx_utils/sgx_utils.h"
#include "time.h"

#define MATRIX_CARD_SIZE 64
#define ENCLAVE_FILE "Enclave.signed.so"

sgx_enclave_id_t global_eid = 0;

// OCall implementations
void ocall_print(const char *str) {
    printf("%s\n", str);
}

void ocall_print_error(const char *str) {
    std::cerr << str << std::endl;
}

void ocall_print_string(const char *str) {
    std::cout << str;
}

void ocall_println_string(const char *str) {
    std::cout << str << std::endl;
}

void ocall_copy_file(const char* src_path, const char* dest_path) {
    FILE* src_file = fopen(src_path, "rb");
    if (src_file == NULL) {
        printf("Unable to open source file for reading.\n");
        return;
    }

    FILE* dest_file = fopen(dest_path, "wb");
    if (dest_file == NULL) {
        printf("Unable to open destination file for writing.\n");
        fclose(src_file);
        return;
    }

    char buffer[4096];
    size_t bytes;

    while ((bytes = fread(buffer, 1, sizeof(buffer), src_file)) > 0) {
        fwrite(buffer, 1, bytes, dest_file);
    }

    fclose(src_file);
    fclose(dest_file);
}

void pretty_print_arr(const uint8_t *data, size_t size, size_t max_per_line) {
    for (size_t i = 0; i < size; ++i) {
        if (i == 0) {
            std::cout << "\t";
        }
        std::cout << std::setw(3) << std::setfill('0') << std::dec << static_cast<int>(data[i]) << ' ';

        if ((i + 1) % max_per_line == 0) {
            std::cout << std::endl
                      << "\t";
        }
    }
    std::cout << std::dec << std::endl;
}

void ocall_text_print(uint8_t *data, uint32_t data_size) {
    for (int i = 0; i < data_size; i++) {
        std::cout << data[i];
    }
    return;
}

void print_usage(char const *argv[]) {
    printf("usage: %s [--generate (generate) | --validate <client_id>]\n", argv[0]);
}

int parse_coords(char const *input, struct Coords **coords_arr) {
    int count = 0;

    const char *ptr = input;

    while ((ptr = strchr(ptr, '=')) != NULL) {
        count++;
        ptr++;
    }

    *coords_arr = (struct Coords *)malloc(count * sizeof(struct Coords));
    if (!*coords_arr) {
        printf("error while parsing coordinates\n");
        exit(1);
    }

    int index = 0;
    ptr = input;
    while (sscanf(ptr, "%c%hhu=%hhu", &((*coords_arr)[index].y), &((*coords_arr)[index].x), &((*coords_arr)[index].val)) == 3) {
        (*coords_arr)[index].y = toupper((*coords_arr)[index].y) - 'A';

        ptr = strchr(ptr, ',');

        if (!ptr) {
            break;
        }

        ptr++;
        index++;
    }

    return count;
}

int main(int argc, char const *argv[]) {
    if (argc <= 1) {
        print_usage(argv);
        return 0;
    }

    ocall_println_string("[-] enclave::starting...");

    int ret;
    sgx_status_t retval;
    if (initialize_enclave(&global_eid, "enclave.token", "enclave.signed.so") < 0) {
        std::cout << "Fail to initialize enclave." << std::endl;
        return 1;
    }

    ocall_println_string("[-] enclave::started");

    if (strcmp(argv[1], "--generate") == 0) {
        ocall_println_string("\t[+] enclave::generate_matrix_card_values");

        // Generate random array
        uint8_t *array = (uint8_t *)malloc(MATRIX_CARD_SIZE * sizeof(uint8_t));
        uint32_t client_id;
        sscanf(argv[2], "%d", &client_id);
        sgx_status_t status = generate_matrix_card_values(global_eid, &ret, client_id, array, MATRIX_CARD_SIZE);
        if (status != SGX_SUCCESS) {
            return 1;
        }

        pretty_print_arr(array, MATRIX_CARD_SIZE, 8);

        //ocall_println_string("\t[+] enclave::sealing");

        //uint32_t arr_size = sizeof(uint8_t) * MATRIX_CARD_SIZE;
        //uint32_t sealed_data_size = 0;
        //ret = get_sealed_data_size(global_eid, &sealed_data_size, arr_size);
        //if (ret != SGX_SUCCESS) {
        //    return -1;
        //}

        //// Seal the array
        //uint8_t *sealed_data_buf = new uint8_t[sealed_data_size];

        //ret = seal_data(global_eid, &retval, array, arr_size, sealed_data_buf, sealed_data_size);

        //if (ret != SGX_SUCCESS) {
        //    ocall_println_string("error");
        //    free(sealed_data_buf);
        //    return -1;
        //}
        //else if (retval != SGX_SUCCESS) {
        //    ocall_println_string("error 2");
        //    free(sealed_data_buf);
        //    return -1;
        //}

        //ocall_println_string("\t[+] enclave::sealed");
        //ecall_insert_matrix_card(global_eid, sealed_data_buf, sealed_data_size);
        return 0;
    }

    if (strcmp(argv[1], "--validate") == 0) {
        if (argc != 4) {
            print_usage(argv);
            return 0;
        }

        struct Coords *coords_arr = NULL;
        int num_records = parse_coords(argv[3], &coords_arr);

        printf("\n");
        for (int i = 0; i < num_records; i++) {
            printf("coords to check %d: x=%hhu, y=%hhu, val=%hhu\n", i, coords_arr[i].x, coords_arr[i].y, coords_arr[i].val);
        }

        uint8_t result = 0;
        uint32_t client_id;
        sscanf(argv[2], "%d", &client_id);

        time_t timestamp = time(NULL);

        int ret = ecall_validate_coords(global_eid, &retval, client_id, coords_arr, num_records, &result, (uint64_t) timestamp);

        printf("\n -- validation result %s\n", result == 1 ? "true": "false");

        return 0;
    }

    return 1;
}
