#ifndef _OCALL_TYPES_H_
#define _OCALL_TYPES_H_

typedef struct Coords {
    uint8_t x;
    uint8_t y;
    uint8_t val;
} Coords;

typedef struct PublicKey
{
    uint8_t gx[32];
    uint8_t gy[32];
} PublicKey; 

typedef struct Signature
{
    uint8_t r[32];
    uint8_t s[32];
} Signature;

#endif