#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>

void ocall_print(const char *str) {
    printf("%s\n", str);
}

int ocall_write_sealed_data(uint32_t client_id, uint8_t *sealed_data, size_t sealed_data_size) {
    char file_name[20];
    sprintf(file_name, "cards/%d", client_id);

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

int ocall_get_sealed_data_size(uint32_t client_id, size_t *file_size) {
    char file_name[20];
    sprintf(file_name, "cards/%d", client_id);

    FILE* file = fopen(file_name, "rb");
    if (file == NULL) {
        printf("Error opening file\n");
        return -1;
    }

    fseek(file, 0, SEEK_END);
    *file_size = ftell(file);
    fclose(file);

    return 0;
}

int ocall_read_sealed_data(uint32_t client_id, uint8_t* data, size_t data_size) {
    char file_name[20];
    sprintf(file_name, "cards/%d", client_id);

    // Open the file for reading
    FILE* file = fopen(file_name, "rb");
    if (file == NULL) {
        printf("Error opening file for reading\n");
        return -1;
    }

    // Read the data from the file
    size_t num_read = fread(data, 1, data_size, file);
    if (num_read != data_size) {
        printf("Error reading data from file\n");
        fclose(file);
        return -1;
    }

    // Close the file
    fclose(file);

    return 0;
}