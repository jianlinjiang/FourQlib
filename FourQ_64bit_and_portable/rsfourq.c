#include "FourQ_internal.h"
#include "FourQ_params.h"
#include "FourQ.h"
#include "FourQ_api.h"
#include "../sha512/sha512.h"
#include <stdio.h>
#include <string.h>

digit_t g_s_plain[4];
digit_t g_s_inv_plain[4];

int oprf_set_sk(const uint8_t* sk) {
    digit_t s[4];
    to_Montgomery((const digit_t*)sk, s);
    from_Montgomery(s, g_s_plain);
    return ECCRYPTO_SUCCESS;
}

int oprf_hash_and_encrypt(const uint8_t* data, const size_t data_len, uint8_t* res) {
    unsigned char HashedValue[64];
    CryptoHashFunction(data, data_len, HashedValue);
    f2elm_t* f2elmt = (f2elm_t*)&HashedValue[0];
    mod1271(((felm_t*)f2elmt)[0]);
    mod1271(((felm_t*)f2elmt)[1]);
    point_t P;
    ECCRYPTO_STATUS Status = HashToCurve((felm_t*)f2elmt, P);
    if (Status != ECCRYPTO_SUCCESS) {
        return Status;
    }
    if (!ecc_mul(P, (digit_t*)g_s_plain, P, false)) {
        return ECCRYPTO_ERROR;
    }
    encode(P, res);
    // memcpy(res, &P, sizeof(point_t));
    return ECCRYPTO_SUCCESS;
}

int oprf_hash_to_curve(const uint8_t* data, const size_t data_len, uint8_t* res) {
    unsigned char HashedValue[64];
    CryptoHashFunction(data, data_len, HashedValue);
    f2elm_t* f2elmt = (f2elm_t*)&HashedValue[0];
    mod1271(((felm_t*)f2elmt)[0]);
    mod1271(((felm_t*)f2elmt)[1]);
    point_t P;
    ECCRYPTO_STATUS Status = HashToCurve((felm_t*)f2elmt, P);
    if (Status != ECCRYPTO_SUCCESS) {
        return Status;
    }
    memcpy(res, &P, sizeof(point_t));
    return ECCRYPTO_SUCCESS;
}

int oprf_encrypt(const uint8_t* point, const size_t point_len, uint8_t* res) {
    point_t P;
    if (point_len != sizeof(point_t)) { return ECCRYPTO_ERROR; }
    memcpy(&P, point, point_len);
    // digit_t s[4], s_plain[4];
    // to_Montgomery((const digit_t*)sk, s);
    // from_Montgomery(s, s_plain);
    if (!ecc_mul(P, (digit_t*)g_s_plain, P, false)) {
        return ECCRYPTO_ERROR;
    }

    memcpy(res, &P, sizeof(point_t));
    return ECCRYPTO_SUCCESS;
}

int oprf_encrypt_compressed(const uint8_t* compressed_point, const size_t point_len, uint8_t* res) {
    point_t P;
    if (point_len != sizeof(point_t) / 2) { return ECCRYPTO_ERROR; }
    decode(compressed_point, P);
    // digit_t s[4], s_plain[4];
    // to_Montgomery((const digit_t*)sk, s);
    // from_Montgomery(s, s_plain);
    if (!ecc_mul(P, (digit_t*)g_s_plain, P, false)) {
        return ECCRYPTO_ERROR;
    }
    encode(P, res);
    return ECCRYPTO_SUCCESS;
}

int oprf_decrypt(const uint8_t* point, const size_t point_len, uint8_t* res) {
    point_t P;
    if (point_len != sizeof(point_t)) { return ECCRYPTO_ERROR; }
    memcpy(&P, point, point_len);
    // digit_t s[4], s_inv[4], s_inv_plain[4];
    // to_Montgomery((const digit_t*)sk, s);

    // find the inverse of s
    // Montgomery_inversion_mod_order(s, s_inv);
    // from_Montgomery(s_inv, s_inv_plain);
    if (!ecc_mul(P, (digit_t*)g_s_inv_plain, P, false)) {
        return ECCRYPTO_ERROR;
    }

    memcpy(res, &P, sizeof(point_t));
    return ECCRYPTO_SUCCESS;
}


// set inverse of s
int oprf_set_sk_inverse(const uint8_t* sk) {
    digit_t s[4], s_inv[4];
    to_Montgomery((const digit_t*)sk, s);
    Montgomery_inversion_mod_order(s, s_inv);
    from_Montgomery(s_inv, g_s_inv_plain);
    return ECCRYPTO_SUCCESS;
}

int oprf_decrypt_compressed(const uint8_t* compressed_point, const size_t point_len, uint8_t* res) {
    point_t P;
    if (point_len != sizeof(point_t) / 2) { return ECCRYPTO_ERROR; }
    decode(compressed_point, P);
    if (!ecc_mul(P, (digit_t*)g_s_inv_plain, P, false)) {
        return ECCRYPTO_ERROR;
    }
    encode(P, res);
    return ECCRYPTO_SUCCESS;
}