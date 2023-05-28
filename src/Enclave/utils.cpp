#include "headers/utils.h"

#include <stdlib.h>
#include <stdio.h>

#include "Enclave_t.h"

void printf(char *format, ...) {
    char buff[128];
    va_list args;
    va_start(args, format);
    vsnprintf(buff, sizeof(buff), format, args);
    va_end(args);
    ocall_print(buff);
}