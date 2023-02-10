#include "FourQ_internal.h"
#include "FourQ_params.h"
#include "FourQ.h"
#include "FourQ_api.h"
#include "../sha512/sha512.h"
#include <stdio.h>
#include <string.h>

int oprf_hash_to_curve(const uint8_t* data, const size_t data_len, uint8_t* res, size_t* res_len) {
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
    *res_len = sizeof(point_t); 
    memcpy(res, &P, *res_len);
    return ECCRYPTO_SUCCESS;
}

// input key is the id
// sk is the secret key of receiver
int oprf_receiver_encrypt(const uint8_t* key, const size_t key_len, const uint64_t* sk, uint8_t* res, size_t* res_len) {
    unsigned char HashedValue[64];
    CryptoHashFunction(key, key_len, HashedValue);
    f2elm_t* f2elmt = (f2elm_t*)&HashedValue[0];
    // trun into  P(2^127-1)
    mod1271(((felm_t*)f2elmt)[0]);
    mod1271(((felm_t*)f2elmt)[1]);
    point_t P;
    // hash key to Point
    ECCRYPTO_STATUS Status = HashToCurve((felm_t*)f2elmt, P);
    if (Status != ECCRYPTO_SUCCESS) {
        return Status;
    }
    // sk**P
    digit_t s[4], c[4];
    to_Montgomery((const digit_t*)sk, s);
    from_Montgomery(s, c);
    if (!ecc_mul(P, (digit_t*)c, P, false)) {
        return ECCRYPTO_ERROR;
    }
    // save P to res
    *res_len = sizeof(point_t); 
    memcpy(res, &P, *res_len);
    return Status;
}

int oprf_receiver_decrypt(const uint8_t* point, const size_t point_len, const uint64_t* sk, uint8_t* res, size_t* res_len) {
    point_t P;
    if (point_len != sizeof(point_t)) { return ECCRYPTO_ERROR; }
    memcpy(&P, point, point_len);
    digit_t s[4], s_inv[4], s_inv_plain[4];
    to_Montgomery((const digit_t*)sk, s);

    Montgomery_inversion_mod_order(s, s_inv);
    from_Montgomery(s_inv, s_inv_plain);
    point_t X;
    if (!ecc_mul(P, (digit_t*)s_inv_plain, P, false)) {
        return ECCRYPTO_ERROR;
    }

    *res_len = sizeof(point_t); 
    memcpy(res, &P, *res_len);
    return ECCRYPTO_SUCCESS;
}