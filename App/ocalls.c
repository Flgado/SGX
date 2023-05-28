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
    struct stat st = {0};
    if (stat("cards", &st) == -1) {
        mkdir("cards", 0700);
    }

    char file_name[20];
    sprintf(file_name, "cards/%d", client_id);

    FILE *file = fopen(file_name, "wb");
    if (file == NULL) {
        printf("** error opening file %s for writing\n", file_name);
        return -1;
    }

    size_t num_written = fwrite(sealed_data, 1, sealed_data_size, file);
    if (num_written != sealed_data_size) {
        printf("** error writing sealed data to file %s\n", file_name);
        fclose(file);
        return -1;
    }

    fclose(file);
    return 0;
}

int ocall_get_sealed_data_size(uint32_t client_id, size_t *file_size) {
    struct stat st = {0};
    if (stat("cards", &st) == -1) {
        mkdir("cards", 0700);
    }

    char file_name[20];
    sprintf(file_name, "cards/%d", client_id);

    FILE* file = fopen(file_name, "rb");
    if (file == NULL) {
        printf("** error opening file %s\n", file_name);
        return -1;
    }

    fseek(file, 0, SEEK_END);
    *file_size = ftell(file);
    fclose(file);

    return 0;
}

int ocall_read_sealed_data(uint32_t client_id, uint8_t* data, size_t data_size) {
    struct stat st = {0};
    if (stat("cards", &st) == -1) {
        mkdir("cards", 0700);
    }

    char file_name[20];
    sprintf(file_name, "cards/%d", client_id);

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

int ocall_get_signature_private_key_data_size(size_t *file_size) {
    struct stat st = {0};
    if (stat("keys/priv", &st) == -1) {
       return -1;
    }

    // Open the file for reading
    FILE* file = fopen("keys/priv", "rb");
    if (file == NULL) {
        printf("Error opening file for reading\n");
        return -1;
    }

    fseek(file, 0, SEEK_END);
    *file_size = ftell(file);
    fclose(file);

    return 0;
}

int ocall_load_signature_private_key(uint8_t *sealed_data, size_t sealed_data_size) {
    struct stat st = {0};
    if (stat("keys/priv", &st) == -1) {
       return -1;
    }

    // Open the file for reading
    FILE* file = fopen("keys/priv", "rb");
    if (file == NULL) {
        printf("Error opening file for reading\n");
        return -1;
    }

    // Read the data from the file
    size_t num_read = fread(sealed_data, 1, sealed_data_size, file);
    if (num_read != sealed_data_size) {
        printf("Error reading data from file\n");
        fclose(file);
        return -1;
    }

    // Close the file
    fclose(file);

    return 0;
}


int ocall_write_sealed_private_key(uint8_t *sealed_data, size_t sealed_data_size) {
    struct stat st = {0};
    if (stat("keys", &st) == -1) {
        mkdir("keys", 0700);
    }

    char file_name[20];
    sprintf(file_name, "keys/%s", "priv");

    FILE *file = fopen(file_name, "wb");
    if (file == NULL) {
        printf("Error opening file for writing\n");
        return -1;
    }

    size_t num_written = fwrite(sealed_data, 1, sealed_data_size, file);
    if (num_written != sealed_data_size) {
        printf("Error writing sealed data to file\n");
        fclose(file);
        return -1;
    }

    fclose(file);
    return 0;
}