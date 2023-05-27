#ifndef _OCALL_TYPES_H_
#define _OCALL_TYPES_H_

typedef struct Coords {
    uint8_t x;
    uint8_t y;
    uint8_t pos;
    uint8_t val;
} Coords;

typedef struct ECDSA256PublicKey {
    uint8_t gx[32];
    uint8_t gy[32];
} ECDSA256PublicKey; 

typedef struct ECDSA256Signature {
    uint8_t r[32];
    uint8_t s[32];
} ECDSA256Signature;

typedef struct EncryptedParam {
    uint8_t *ciphertext;
    uint8_t *tag;
    size_t cipher_size;
    size_t tag_size;
} EncryptedParam;

#endif