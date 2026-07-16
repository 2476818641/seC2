#include "Crypt.h"
#include "utils.h"

// AES-128 S-box
static const unsigned char sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

#define ROTL8(x) (((x) << 1) | ((x) >> 7))

static void aes_key_expansion(const unsigned char* key, unsigned char* rk)
{
    int i;
    unsigned char* rk_ptr = rk;
    for (i = 0; i < 16; i++)
        rk_ptr[i] = key[i];

    unsigned char tmp[4];
    int rcon = 1;
    rk_ptr += 16;

    for (i = 16; i < 176; i += 4) {
        tmp[0] = rk_ptr[-4];
        tmp[1] = rk_ptr[-3];
        tmp[2] = rk_ptr[-2];
        tmp[3] = rk_ptr[-1];

        if (i % 16 == 0) {
            unsigned char t = tmp[0];
            tmp[0] = sbox[tmp[1]] ^ rcon;
            tmp[1] = sbox[tmp[2]];
            tmp[2] = sbox[tmp[3]];
            tmp[3] = sbox[t];
            rcon = ROTL8(rcon);
        }

        rk_ptr[0] = rk_ptr[-16] ^ tmp[0];
        rk_ptr[1] = rk_ptr[-15] ^ tmp[1];
        rk_ptr[2] = rk_ptr[-14] ^ tmp[2];
        rk_ptr[3] = rk_ptr[-13] ^ tmp[3];
        rk_ptr += 4;
    }
}

static void aes_encrypt_block(const unsigned char* in, unsigned char* out, const unsigned char* rk)
{
    unsigned char s[16];
    int i;
    for (i = 0; i < 16; i++)
        s[i] = in[i] ^ rk[i];

    for (int round = 1; round <= 9; round++) {
        const unsigned char* rkp = rk + round * 16;
        unsigned char t[16];
        t[0]  = sbox[s[0]];  t[1]  = sbox[s[5]];  t[2]  = sbox[s[10]]; t[3]  = sbox[s[15]];
        t[4]  = sbox[s[4]];  t[5]  = sbox[s[9]];  t[6]  = sbox[s[14]]; t[7]  = sbox[s[3]];
        t[8]  = sbox[s[8]];  t[9]  = sbox[s[13]]; t[10] = sbox[s[2]];  t[11] = sbox[s[7]];
        t[12] = sbox[s[12]]; t[13] = sbox[s[1]];  t[14] = sbox[s[6]];  t[15] = sbox[s[11]];

        // MixColumns via xtime
        for (int c = 0; c < 4; c++) {
            int idx = c * 4;
            unsigned char a0 = t[idx], a1 = t[idx+1], a2 = t[idx+2], a3 = t[idx+3];
            unsigned char x = (unsigned char)((signed char)a0 >> 7);
            unsigned char y = a0 << 1;
            y ^= (x & 0x1B);
            unsigned char a02 = y;
            x = (unsigned char)((signed char)a1 >> 7);
            y = a1 << 1;
            y ^= (x & 0x1B);
            unsigned char a12 = y;
            x = (unsigned char)((signed char)a2 >> 7);
            y = a2 << 1;
            y ^= (x & 0x1B);
            unsigned char a22 = y;
            x = (unsigned char)((signed char)a3 >> 7);
            y = a3 << 1;
            y ^= (x & 0x1B);
            unsigned char a32 = y;

            s[idx]   = a02 ^ a1 ^ a12 ^ a2 ^ a3 ^ rkp[idx];
            s[idx+1] = a0 ^ a12 ^ a2 ^ a22 ^ a3 ^ rkp[idx+1];
            s[idx+2] = a0 ^ a1 ^ a22 ^ a3 ^ a32 ^ rkp[idx+2];
            s[idx+3] = a02 ^ a0 ^ a1 ^ a32 ^ a3 ^ rkp[idx+3];
        }
    }

    const unsigned char* rkp = rk + 160;
    // Final round: no MixColumns, just ShiftRows + SubBytes + AddRoundKey
    out[0]  = sbox[s[0]];  out[1]  = sbox[s[5]];  out[2]  = sbox[s[10]]; out[3]  = sbox[s[15]];
    out[4]  = sbox[s[4]];  out[5]  = sbox[s[9]];  out[6]  = sbox[s[14]]; out[7]  = sbox[s[3]];
    out[8]  = sbox[s[8]];  out[9]  = sbox[s[13]]; out[10] = sbox[s[2]];  out[11] = sbox[s[7]];
    out[12] = sbox[s[12]]; out[13] = sbox[s[1]];  out[14] = sbox[s[6]];  out[15] = sbox[s[11]];
    for (i = 0; i < 16; i++)
        out[i] ^= rkp[i];
}

// GF(2^128) multiplication helpers
static void gf_mul(unsigned char* x, const unsigned char* y)
{
    unsigned char v[16];
    int i;
    for (i = 0; i < 16; i++) v[i] = 0;

    for (i = 0; i < 128; i++) {
        int byte_idx = i / 8;
        int bit_idx = 7 - (i % 8);
        if (y[byte_idx] & (1 << bit_idx)) {
            for (int j = 0; j < 16; j++)
                v[j] ^= x[j];
        }
        unsigned char carry = (unsigned char)((signed char)x[15] >> 7);
        for (int j = 15; j > 0; j--)
            x[j] = (unsigned char)((x[j] << 1) | (x[j-1] >> 7));
        x[0] <<= 1;
        if (carry)
            x[0] ^= 0xE1;
    }

    for (i = 0; i < 16; i++)
        x[i] = v[i];
}

static void ghash(unsigned char* h, const unsigned char* aad, int aadLen,
                  const unsigned char* ciphertext, int cipherLen,
                  unsigned char* out)
{
    unsigned char tmp[16];
    int i;
    for (i = 0; i < 16; i++) tmp[i] = 0;

    // Process AAD
    int pos = 0;
    while (pos < aadLen) {
        int chunk = aadLen - pos;
        if (chunk > 16) chunk = 16;
        for (int j = 0; j < chunk; j++)
            tmp[j] ^= aad[pos + j];
        for (int j = chunk; j < 16; j++)
            tmp[j] ^= 0;
        gf_mul(tmp, h);
        pos += chunk;
    }

    // Process ciphertext
    pos = 0;
    while (pos < cipherLen) {
        int chunk = cipherLen - pos;
        if (chunk > 16) chunk = 16;
        for (int j = 0; j < chunk; j++)
            tmp[j] ^= ciphertext[pos + j];
        for (int j = chunk; j < 16; j++)
            tmp[j] ^= 0;
        gf_mul(tmp, h);
        pos += chunk;
    }

    // Length block
    unsigned long long aadBits = (unsigned long long)aadLen * 8;
    unsigned long long cipherBits = (unsigned long long)cipherLen * 8;

    unsigned char lenBlock[16];
    for (i = 0; i < 8; i++) {
        lenBlock[i] = (unsigned char)(aadBits >> (56 - i * 8));
        lenBlock[i+8] = (unsigned char)(cipherBits >> (56 - i * 8));
    }
    for (i = 0; i < 16; i++)
        tmp[i] ^= lenBlock[i];
    gf_mul(tmp, h);

    for (i = 0; i < 16; i++)
        out[i] = tmp[i];
}

static void aes_ctr_increment(unsigned char* ctr)
{
    for (int i = 15; i >= 0; i--) {
        ctr[i]++;
        if (ctr[i] != 0)
            break;
    }
}

void AESGCMEncrypt(const unsigned char* plaintext, int plainLen,
                   const unsigned char* key, unsigned char* nonceOut,
                   unsigned char* ciphertext, unsigned char* tagOut)
{
    unsigned char rk[176];
    aes_key_expansion(key, rk);

    // Generate random nonce
    for (int i = 0; i < 12; i++)
        nonceOut[i] = GenerateRandom32() & 0xFF;

    // Build initial counter: nonce || counter(4 bytes, start at 1)
    unsigned char ctr[16];
    for (int i = 0; i < 12; i++)
        ctr[i] = nonceOut[i];
    ctr[12] = 0; ctr[13] = 0; ctr[14] = 0; ctr[15] = 1;

    // Encrypt with CTR mode
    int pos = 0;
    unsigned char keystream[16];
    while (pos < plainLen) {
        aes_encrypt_block(ctr, keystream, rk);
        int chunk = plainLen - pos;
        if (chunk > 16) chunk = 16;
        for (int j = 0; j < chunk; j++)
            ciphertext[pos + j] = plaintext[pos + j] ^ keystream[j];
        pos += chunk;
        aes_ctr_increment(ctr);
    }

    // Compute H = AES(key, zeros)
    unsigned char zeros[16];
    for (int i = 0; i < 16; i++) zeros[i] = 0;
    unsigned char h[16];
    aes_encrypt_block(zeros, h, rk);

    // Compute GHASH(aad || ciphertext || len64)
    ghash(h, NULL, 0, ciphertext, plainLen, tagOut);

    // XOR with AES(key, nonce || 0x00000001)
    unsigned char j0[16];
    for (int i = 0; i < 12; i++) j0[i] = nonceOut[i];
    j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;
    aes_encrypt_block(j0, j0, rk);
    for (int i = 0; i < 16; i++)
        tagOut[i] ^= j0[i];
}

int AESGCMDecrypt(const unsigned char* ciphertext, int cipherLen,
                  const unsigned char* key, const unsigned char* nonce,
                  unsigned char* plaintext, const unsigned char* tag)
{
    unsigned char rk[176];
    aes_key_expansion(key, rk);

    // Compute H
    unsigned char zeros[16];
    for (int i = 0; i < 16; i++) zeros[i] = 0;
    unsigned char h[16];
    aes_encrypt_block(zeros, h, rk);

    // Verify tag
    unsigned char computedTag[16];
    ghash(h, NULL, 0, ciphertext, cipherLen, computedTag);

    unsigned char j0[16];
    for (int i = 0; i < 12; i++) j0[i] = nonce[i];
    j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;
    aes_encrypt_block(j0, j0, rk);
    for (int i = 0; i < 16; i++)
        computedTag[i] ^= j0[i];

    // Constant-time tag comparison
    unsigned char diff = 0;
    for (int i = 0; i < 16; i++)
        diff |= (computedTag[i] ^ tag[i]);

    if (diff != 0)
        return 0; // Authentication failed

    // Decrypt with CTR mode
    unsigned char ctr[16];
    for (int i = 0; i < 12; i++)
        ctr[i] = nonce[i];
    ctr[12] = 0; ctr[13] = 0; ctr[14] = 0; ctr[15] = 1;

    int pos = 0;
    unsigned char keystream[16];
    while (pos < cipherLen) {
        aes_encrypt_block(ctr, keystream, rk);
        int chunk = cipherLen - pos;
        if (chunk > 16) chunk = 16;
        for (int j = 0; j < chunk; j++)
            plaintext[pos + j] = ciphertext[pos + j] ^ keystream[j];
        pos += chunk;
        aes_ctr_increment(ctr);
    }

    return 1;
}

void RC4Init(unsigned char* key, unsigned char* S, int keyLength) {
    int i, j = 0;
    unsigned char temp;

    for (i = 0; i < 256; i++) {
        S[i] = (unsigned char)i;
    }

    for (i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % keyLength]) % 256;
        temp = S[i];
        S[i] = S[j];
        S[j] = temp;
    }
}

void RC4EncryptDecrypt(unsigned char* data, int dataLength, unsigned char* S) {
    int i = 0, j = 0, k;
    unsigned char temp;

    for (k = 0; k < dataLength; k++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;

        temp = S[i];
        S[i] = S[j];
        S[j] = temp;

        data[k] ^= S[(S[i] + S[j]) % 256];
    }
}

void EncryptRC4(unsigned char* data, int dataLength, unsigned char* key, int keyLength) {
    unsigned char S[256];
    RC4Init(key, S, keyLength);
    RC4EncryptDecrypt(data, dataLength, S);
}

void DecryptRC4(unsigned char* data, int dataLength, unsigned char* key, int keyLength) {
    EncryptRC4(data, dataLength, key, keyLength);
}
