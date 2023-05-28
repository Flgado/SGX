#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>

void ocall_print(const char *str) {
    printf("  ENCLAVE: %s", str);
}

void ocall_print_error(const char *str) {
    printf("\033[0;31m ENCLAVE ERROR: %s", str);
    printf("\033[0;0m");
}

int ocall_write_sealed_data(uint32_t client_id, uint8_t *sealed_data, size_t sealed_data_size) {
    char file_name[20];
    sprintf(file_name, "cards/%d", client_id);
    return write_data((const char*) "cards", file_name, sealed_data, sealed_data_size);
}

int ocall_write_sealed_private_key(uint8_t *sealed_data, size_t sealed_data_size) {
    return write_data((const char*) "keys", (const char*) "keys/priv", sealed_data, sealed_data_size);
}

int ocall_get_signature_private_key_data_size(size_t *file_size) {
    return get_file_size((const char *) "keys/priv", file_size);
}

int ocall_get_sealed_data_size(uint32_t client_id, size_t *file_size) {
    char file_name[20];
    sprintf(file_name, "cards/%d", client_id);
    return get_file_size((const char *) file_name, file_size);
}

int ocall_read_sealed_data(uint32_t client_id, uint8_t* data, size_t data_size) {
    char file_name[20];
    sprintf(file_name, "cards/%d", client_id);
    return read_data_from_file((const char *) file_name, data, data_size);
}

int ocall_load_signature_private_key(uint8_t *sealed_data, size_t sealed_data_size) {
    return read_data_from_file((const char *) "keys/priv", sealed_data, sealed_data_size);
}

int write_data(const char *base_folder, const char *file_name, uint8_t *data, size_t data_size) {
    struct stat st = {0};
    if (stat(base_folder, &st) == -1) {
        mkdir(base_folder, 0700);
    }

    FILE *file = fopen(file_name, "wb");
    if (file == NULL) {
        printf("** error opening file %s for writing\n", file_name);
        return -1;
    }

    size_t num_written = fwrite(data, 1, data_size, file);
    if (num_written != data_size) {
        printf("** error writing data to file %s\n", file_name);
        fclose(file);
        return -1;
    }

    fclose(file);
    return 0;
}

int get_file_size(const char *file_name, size_t *file_size) {
    struct stat st = {0};
    if (stat(file_name, &st) == -1) {
       return -1;
    }

    // Open the file for reading
    FILE* file = fopen(file_name, "rb");
    if (file == NULL) {
        printf("Error opening file for reading\n");
        return -1;
    }

    fseek(file, 0, SEEK_END);
    *file_size = ftell(file);
    fclose(file);

    return 0;
}

int read_data_from_file(const char *file_name, uint8_t *data, size_t data_size) {
    // Open the file for reading
    FILE* file = fopen(file_name, "rb");
    if (file == NULL) {
        printf("** error opening file %s for reading\n", file_name);
        return -1;
    }

    // Read the data from the file
    size_t num_read = fread(data, 1, data_size, file);
    if (num_read != data_size) {
        printf("** error reading data from file %s\n", file_name);
        fclose(file);
        return -1;
    }

    fclose(file);

    return 0;
}