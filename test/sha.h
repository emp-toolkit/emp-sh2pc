#ifndef _SHA_H_
#define _SHA_H_

#include <stdint.h>

enum {
    shaSuccess = 0,
    shaNull,
    shaInputTooLong,
    shaStateError,
    shaBadParam
};
#endif 

#ifndef _SHA_enum_
#define _SHA_enum_

enum {
    SHA1_Message_Block_Size = 64, SHA224_Message_Block_Size = 64,
    SHA256_Message_Block_Size = 64, SHA384_Message_Block_Size = 128,
    SHA512_Message_Block_Size = 128,
    USHA_Max_Message_Block_Size = SHA512_Message_Block_Size,

SHA1HashSize = 20, SHA224HashSize = 28, SHA256HashSize = 32,
SHA384HashSize = 48, SHA512HashSize = 64,
USHAMaxHashSize = SHA512HashSize,
SHA1HashSizeBits = 160, SHA224HashSizeBits = 224,
SHA256HashSizeBits = 256, SHA384HashSizeBits = 384,
SHA512HashSizeBits = 512, USHAMaxHashSizeBits = SHA512HashSizeBits
};
/*
 *  These constants are used in the USHA (Unified SHA) functions.
 */
typedef enum SHAversion {
    SHA_1, SHA_224, SHA_256, SHA_384, SHA_512
} SHAversion;
/*
 *  This structure will hold context information for the SHA-1
 *  hashing operation.
 */
typedef struct SHA1Context {
    uint32_t Intermediate_Hash[SHA1HashSize/4]; /* Message Digest */
    uint32_t Length_High;               /* Message length in bits */
    uint32_t Length_Low;                /* Message length in bits */
    int_least16_t Message_Block_Index;  /* Message_Block array index */
                                        /* 512-bit message blocks */
    uint8_t Message_Block[SHA1_Message_Block_Size];
    int Computed;                   /* Is the hash computed? */
    int Corrupted;                  /* Cumulative corruption code */
} SHA1Context;
/*
 *  This structure will hold context information for the SHA-256
 *  hashing operation.
 */
typedef struct SHA256Context {
    uint32_t Intermediate_Hash[SHA256HashSize/4]; /* Message Digest */
    uint32_t Length_High;               /* Message length in bits */
    uint32_t Length_Low;                /* Message length in bits */
    int_least16_t Message_Block_Index;  /* Message_Block array index */
                                        /* 512-bit message blocks */
    uint8_t Message_Block[SHA256_Message_Block_Size];


    int Computed;
    int Corrupted;
} SHA256Context;
/* Is the hash computed? */
/* Cumulative corruption code */
/*
 *  This structure will hold context information for the SHA-512
 *  hashing operation.
 */
typedef struct SHA512Context {
#ifdef USE_32BIT_ONLY
    uint32_t Intermediate_Hash[SHA512HashSize/4]; /* Message Digest  */
    uint32_t Length[4];                 /* Message length in bits */
#else /* !USE_32BIT_ONLY */
    uint64_t Intermediate_Hash[SHA512HashSize/8]; /* Message Digest */
    uint64_t Length_High, Length_Low;   /* Message length in bits */
#endif /* USE_32BIT_ONLY */
    int_least16_t Message_Block_Index;  /* Message_Block array index */
                                        /* 1024-bit message blocks */
    uint8_t Message_Block[SHA512_Message_Block_Size];
    int Computed;                   /* Is the hash computed?*/
    int Corrupted;                  /* Cumulative corruption code */
} SHA512Context;
/*
 *  This structure will hold context information for the SHA-224
 *  hashing operation.  It uses the SHA-256 structure for computation.
 */
typedef struct SHA256Context SHA224Context;
/*
 *  This structure will hold context information for the SHA-384
 *  hashing operation.  It uses the SHA-512 structure for computation.
 */
typedef struct SHA512Context SHA384Context;
/*
 *  This structure holds context information for all SHA
 *  hashing operations.
 */
typedef struct USHAContext {
    int whichSha;
/* which SHA is being used */
    union {
      SHA1Context sha1Context;
      SHA224Context sha224Context; SHA256Context sha256Context;
      SHA384Context sha384Context; SHA512Context sha512Context;
} ctx;



} USHAContext;
/*
 *  This structure will hold context information for the HMAC
 *  keyed-hashing operation.
 */
typedef struct HMACContext {
    int whichSha;
/* which SHA is being used */
/* hash size of SHA being used */
/* block size of SHA being used */
/* SHA context */
int hashSize;
int blockSize;
unsigned char k_opad[USHA_Max_Message_Block_Size];
                        /* outer padding - key XORd with opad */
    int Computed;               /* Is the MAC computed? */
    int Corrupted;              /* Cumulative corruption code */
} HMACContext;
/*
 *  This structure will hold context information for the HKDF
 *  extract-and-expand Key Derivation Functions.
 */
typedef struct HKDFContext {
    int whichSha;               /* which SHA is being used */
    HMACContext hmacContext;
    int hashSize;               /* hash size of SHA being used */
    unsigned char prk[USHAMaxHashSize];
    int Computed;
    int Corrupted;
} HKDFContext;
/*
 *  Function Prototypes
 */
/* pseudo-random key - output of hkdfInput */
        /* Is the key material computed? */
        /* Cumulative corruption code */
/* SHA-1 */
extern int SHA1Reset(SHA1Context *);
extern int SHA1Input(SHA1Context *, const uint8_t *bytes,
                     unsigned int bytecount);
extern int SHA1FinalBits(SHA1Context *, uint8_t bits,
                         unsigned int bit_count);
extern int SHA1Result(SHA1Context *,
                      uint8_t Message_Digest[SHA1HashSize]);

/* SHA-224 */
extern int SHA224Reset(SHA224Context *);
extern int SHA224Input(SHA224Context *, const uint8_t *bytes,
                       unsigned int bytecount);
extern int SHA224FinalBits(SHA224Context *, uint8_t bits,
                           unsigned int bit_count);
extern int SHA224Result(SHA224Context *,
                        uint8_t Message_Digest[SHA224HashSize]);
/* SHA-256 */
extern int SHA256Reset(SHA256Context *);
extern int SHA256Input(SHA256Context *, const uint8_t *bytes,
                       unsigned int bytecount);
extern int SHA256FinalBits(SHA256Context *, uint8_t bits,
                           unsigned int bit_count);
extern int SHA256Result(SHA256Context *,
                        uint8_t Message_Digest[SHA256HashSize]);
/* SHA-384 */
extern int SHA384Reset(SHA384Context *);
extern int SHA384Input(SHA384Context *, const uint8_t *bytes,
                       unsigned int bytecount);
extern int SHA384FinalBits(SHA384Context *, uint8_t bits,
                           unsigned int bit_count);
extern int SHA384Result(SHA384Context *,
                        uint8_t Message_Digest[SHA384HashSize]);
/* SHA-512 */
extern int SHA512Reset(SHA512Context *);
extern int SHA512Input(SHA512Context *, const uint8_t *bytes,
                       unsigned int bytecount);
extern int SHA512FinalBits(SHA512Context *, uint8_t bits,
                           unsigned int bit_count);
extern int SHA512Result(SHA512Context *,
                        uint8_t Message_Digest[SHA512HashSize]);
/* Unified SHA functions, chosen by whichSha */
extern int USHAReset(USHAContext *context, SHAversion whichSha);
extern int USHAInput(USHAContext *context,
                     const uint8_t *bytes, unsigned int bytecount);
extern int USHAFinalBits(USHAContext *context,
                         uint8_t bits, unsigned int bit_count);
extern int USHAResult(USHAContext *context,
                      uint8_t Message_Digest[USHAMaxHashSize]);
extern int USHABlockSize(enum SHAversion whichSha);
extern int USHAHashSize(enum SHAversion whichSha);
extern int USHAHashSizeBits(enum SHAversion whichSha);
extern const char *USHAHashName(enum SHAversion whichSha);

/*
 * HMAC Keyed-Hashing for Message Authentication, RFC 2104,
 * for all SHAs.
 * This interface allows a fixed-length text input to be used.
 */
extern int hmac(SHAversion whichSha, /* which SHA algorithm to use */
const unsigned char *text,
int text_len,
const unsigned char *key,
int key_len,
/* pointer to data stream */
/* length of data stream */
/* pointer to authentication key */
/* length of authentication key */
    uint8_t digest[USHAMaxHashSize]); /* caller digest to fill in */
/*
 * HMAC Keyed-Hashing for Message Authentication, RFC 2104,
 * for all SHAs.
 * This interface allows any length of text input to be used.
 */
extern int hmacReset(HMACContext *context, enum SHAversion whichSha,
                     const unsigned char *key, int key_len);
extern int hmacInput(HMACContext *context, const unsigned char *text,
                     int text_len);
extern int hmacFinalBits(HMACContext *context, uint8_t bits,
                         unsigned int bit_count);
extern int hmacResult(HMACContext *context,
                      uint8_t digest[USHAMaxHashSize]);
/*
 * HKDF HMAC-based Extract-and-Expand Key Derivation Function,
 * RFC 5869, for all SHAs.
 */
extern int hkdf(SHAversion whichSha, const unsigned char *salt,
                int salt_len, const unsigned char *ikm, int ikm_len,
                const unsigned char *info, int info_len,
                uint8_t okm[ ], int okm_len);
extern int hkdfExtract(SHAversion whichSha, const unsigned char *salt,
                       int salt_len, const unsigned char *ikm,
                       int ikm_len, uint8_t prk[USHAMaxHashSize]);
extern int hkdfExpand(SHAversion whichSha, const uint8_t prk[ ],
                      int prk_len, const unsigned char *info,
                      int info_len, uint8_t okm[ ], int okm_len);
/*
 * HKDF HMAC-based Extract-and-Expand Key Derivation Function,
 * RFC 5869, for all SHAs.
 * This interface allows any length of text input to be used.
 */
extern int hkdfReset(HKDFContext *context, enum SHAversion whichSha,
                     const unsigned char *salt, int salt_len);

extern int hkdfInput(HKDFContext *context, const unsigned char *ikm,
                     int ikm_len);
extern int hkdfFinalBits(HKDFContext *context, uint8_t ikm_bits,
                         unsigned int ikm_bit_count);
extern int hkdfResult(HKDFContext *context,
                      uint8_t prk[USHAMaxHashSize],
                      const unsigned char *info, int info_len,
                      uint8_t okm[USHAMaxHashSize], int okm_len);
#endif /* _SHA_H_ */