

#include "ed25519.h"
#include "edsign.h"
#include "f25519.h"
#include "fprime.h"
#include "random.h"
#include "hashes/sha512.h"
//for everything that PSA can deliver

#include <stdio.h>
//randomness - but which to take?
//#include "od.h"
#include <stdint.h>

static const uint8_t ed25519_order_little_endian[32] = {
	0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
	0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10};

#define HASH_SIZE PSA_HASH_LENGTH(PSA_ALG_SHA_512)

static uint8_t _uint8t_to_ed25519pt(const uint8_t *from, struct ed25519_pt *to){
    
    uint8_t error = 0;
    uint8_t x[32] = {0};
    uint8_t y[32] = {0};
    error = ed25519_try_unpack(x, y, from);
    //error == 1 signals that unpacked point is on curve
    if(error != 1){
        printf("ed25519_try_unpack returned %d\n", error);
    }
    ed25519_project(to, x, y);
    return error;
}

static void _ed25519pt_to_uint8t(struct ed25519_pt *from, const uint8_t *to){
    uint8_t x[32] = {0};
    uint8_t y[32] = {0};
    ed25519_unproject(x, y, from);
    ed25519_pack((uint8_t *)to, x, y);
}

// uint8_t _calculate_r(const uint8_t *R_value, uint8_t *r_value)
// {
//     // R = rG
//     struct ed25519_pt rG;
//     ed25519_smult(&rG, &ed25519_base, r_value);
//     _ed25519pt_to_uint8t(&rG, R_value);
//     return 0;
// }

uint8_t _calculate_r_dash(uint8_t *a_value,
                        uint8_t *b_value,
                        const uint8_t *denom_pub,
                        uint8_t *R_dash_value,
                        uint8_t *R_value)
{   
    //R' = R + a*G + b*denom_pub for R'0 and R'1
    struct ed25519_pt r_pub;
    struct ed25519_pt r_dash;
    struct ed25519_pt aG;
    struct ed25519_pt bDenomPub;

    //aG
    ed25519_smult(&aG, &ed25519_base, a_value);

    //DenomPub to Point - do this outside of the loop and reuse it
    _uint8t_to_ed25519pt(denom_pub, &bDenomPub);
    //b * denompub
    ed25519_smult(&bDenomPub, &bDenomPub, b_value);

    //aG + bDenomPub
    ed25519_add(&r_dash, &aG, &bDenomPub);

    _uint8t_to_ed25519pt(R_value, &r_pub);
    // R + aG + bdenomPub
    ed25519_add(&r_dash, &r_pub, &r_dash);

    //save in r_dash array
    _ed25519pt_to_uint8t(&r_dash, R_dash_value);
    return 0;
}

/**
 * @brief Calcualtes the c' values as "full domain hashes" of the blinded R (R')
 * values and the message that shall be blinded
 * 
 * First concatenates R' and msg and creates a SHA512 hash, then creates the 
 * full domain hash from that hash. 
 * in short: fdh(SHA512(R', msg))
 * The fdh part ensures that c' is <= group order of curve25519
 * 
 * TODO: At some point, understand properly why the normalization at the end is necessary.
 *       And also the endianness swap. I guess it is because of c25519 working with little endian.
 *      Potential answer: I think it is unnecessary. We only want a number that is a valid
        scalar. We get that as soon as it is smaller L. This we gain trough the hkdf with mod.
        I guess normalize did never do anything other than that. It might be necessary to use
        something like it in case there is no mod used. Then we might end up with a number that
        is potentially larger than L.
 */
uint8_t _calculate_c_dash(uint8_t *R_dash, uint8_t *c_dash,
                        const uint8_t *msg, size_t msg_len)
{
    // c' = HASH(R'_b, msg)
    //do this for both c' values
    //SHA-512 hash R' and message (planchet pub key (!?)) -> prehash
    size_t hash_in_len = 32 + msg_len;
    uint8_t hash_in[hash_in_len];
    memset(hash_in, 0x00, hash_in_len);
    memcpy(hash_in, R_dash, 32);
    memcpy(&hash_in[32], msg, msg_len);

    //create the SHA512(R', msg)
            
    sha512(hash_in, hash_in_len, c_dash);
   
    //make it match to main ed25519 subgroup
    //TODO: Is this actually necessary? 
    //fprime_normalize(c_dash_values[c].priv, ed25519_order_little_endian);
    return 0;
}

uint8_t generate_key_pair( uint8_t *priv_key_buffer,
                                                uint8_t *pub_key_buffer)
{
    /* todo: maybe this should usa psa_random instead */
    random_bytes(priv_key_buffer, EDSIGN_SECRET_KEY_SIZE);
    ed25519_prepare(priv_key_buffer);
    //fprime_normalize(priv_key_buffer,ed25519_order_little_endian);
    struct ed25519_pt p;
    ed25519_smult(&p, &ed25519_base, priv_key_buffer);
    uint8_t x[F25519_SIZE];
	uint8_t y[F25519_SIZE];

	ed25519_unproject(x, y, &p);
	ed25519_pack(pub_key_buffer, x, y);
    //edsign_sec_to_pub(pub_key_buffer, priv_key_buffer);

    return 0;
}

uint8_t bs_cbs_generate_commitment(uint8_t *r0, uint8_t *r1, const uint8_t *output,
                                        size_t size, size_t *length)
{
    if (size < 64) {
        return -1;
    }
    random_bytes(r0, EDSIGN_SECRET_KEY_SIZE);
    fprime_normalize(r0, ed25519_order_little_endian);
  
    struct ed25519_pt r0p;
	ed25519_smult(&r0p, &ed25519_base, r0);
    _ed25519pt_to_uint8t(&r0p, output);

    random_bytes(r1, EDSIGN_SECRET_KEY_SIZE);
    fprime_normalize(r1, ed25519_order_little_endian);

    struct ed25519_pt r1p;
	ed25519_smult(&r1p, &ed25519_base, r1);
    _ed25519pt_to_uint8t(&r1p, &output[32]);

    *length = 64;
    
    return 0;
}

uint8_t bs_cbs_blind_message(
                    const uint8_t *pubkey_data, size_t pubkey_data_len,
                    const uint8_t *input, size_t input_length,
                    const uint8_t *prandom, size_t prandom_length,
                    uint8_t *R0_dash, uint8_t *R1_dash,
                    uint8_t *a0, uint8_t *a1,
                    const uint8_t *output, size_t output_size, size_t *output_length)
{
    if (output_size < 64) {
        return -1;
    }
    if (prandom_length < 64 || pubkey_data_len != 32) {
        return -1;
    }
    // choose random a and b values
    uint8_t b0[32];
    uint8_t b1[32];

    uint8_t R0[32];
    uint8_t R1[32];
    
    memcpy(R0, prandom, 32);
    memcpy(R1, &prandom[32], 32);

    uint8_t c0_dash[32];
    uint8_t c1_dash[32];


    random_bytes(a0, EDSIGN_SECRET_KEY_SIZE);
    fprime_normalize(a0, ed25519_order_little_endian);

    random_bytes(a1, EDSIGN_SECRET_KEY_SIZE);
    fprime_normalize(a1, ed25519_order_little_endian);

    random_bytes(b0, EDSIGN_SECRET_KEY_SIZE);
    fprime_normalize(b0, ed25519_order_little_endian);
   
    random_bytes(b1, EDSIGN_SECRET_KEY_SIZE);
    fprime_normalize(b1, ed25519_order_little_endian);
   
    // save R'
    //calc R' = R + a*G + b*pubkey_data
    uint8_t ret = _calculate_r_dash(a0, b0, pubkey_data, R0_dash, R0);
    if (ret != 0) {
        return ret;
    }
    // puts("R'0");
    // od_hex_dump(R0_dash, 32, 32);

    ret = _calculate_r_dash(a1, b1, pubkey_data, R1_dash, R1);
    if (ret != 0) {
        return ret;
    }
    
    //calc c' = SHA512(R',input)
    // preserve R_dash
    uint8_t tmp[32];
    memcpy(tmp, R0_dash, 32);
    ret = _calculate_c_dash(R0_dash, c0_dash, input, input_length);
    memcpy(R0_dash, tmp, 32);

    if (ret != 0) {
        return ret;
    }

    memcpy(tmp, R1_dash, 32);
    ret = _calculate_c_dash(R1_dash, c1_dash, input, input_length);
    memcpy(R1_dash, tmp, 32);
    if (ret != 0) {
        return ret;
    }
    
    /*
    Done: Test if this also works with fprime_add using the right modulus.
    It does. f25519_add uses modulus 2^255-19. The proper modulus for scalars is the subgroup order L, however.
    Reading the scalar again with the right modulus works as L is smaller then 2^255-19.
    Addition using that modulus directly works just as well.
    Would look like this:
    fprime_add(tmp, c_dash_values[0].priv, ed25519_order_little_endian);
    fprime_add(tmp, b_values[0].priv, ed25519_order_little_endian);

    TODO: Maybe try to see if any of the methods makes a performance difference. 
    Otherwise use the one that is closer to what needs to be done with cryptocell.
    */
    
    //calc c = c' + b mod L    
    // memcpy(tmp, c0_dash, 32);
    // fprime_add(tmp, b0, ed25519_order_little_endian);
    // memcpy((uint8_t *)output, tmp, 32);
    memset(tmp, 0, 32);
    f25519_add(tmp, b0, c0_dash);
    fprime_from_bytes((uint8_t *)output, tmp, 32, ed25519_order_little_endian);

    memset(tmp, 0x00, 32);
    // memcpy(tmp, c1_dash, 32);
    // fprime_add(tmp, b1, ed25519_order_little_endian);
    // memcpy((uint8_t *)&output[32], tmp, 32);
    f25519_add(tmp, b1, c1_dash);
    fprime_from_bytes((uint8_t *)&output[32], tmp, 32, ed25519_order_little_endian);
    
    *output_length = 64;

    return 0;
}

uint8_t bs_cbs_sign_message(
                                    uint8_t *priv_key, size_t key_bytes, const uint8_t *bmessage, size_t bsize,
                                    uint8_t *r0, uint8_t *r1, 
                                    uint8_t *bsignature, size_t bs_size, size_t *bs_length)
{
    uint8_t b_offset;
    random_bytes(&b_offset, sizeof(b_offset));
    if (bs_size < 32 + 1 || bsize < 33) {
        return -1;
    }
    if (key_bytes != 32) {
        return -1;
    }
    
    b_offset = (b_offset % 2) ? 0 : 32;
    // using the first byte as indicator of index 0 or 1
    bsignature[0] = (b_offset) ? 0x00 : 0xff;
    // s = r[b_offset] + c[b_offset] * x mod p

    //cx = c * x
    uint8_t cx[32];
    fprime_mul(cx, &bmessage[b_offset], priv_key, ed25519_order_little_endian);
    uint8_t tmp[32];
    if (b_offset == 0) {
        //fprime_add(&bsignature[1], r0, ed25519_order_little_endian);
        f25519_add(tmp, r0, cx);
        fprime_from_bytes(&bsignature[1], tmp, 32, ed25519_order_little_endian);
    }
    else {
        //fprime_add(&bsignature[1], r1, ed25519_order_little_endian);
        f25519_add(tmp, r1, cx);
        fprime_from_bytes(&bsignature[1], tmp, 32, ed25519_order_little_endian);
    }
    *bs_length = 33;
    return 0;
}

void __print_ed_point(const struct ed25519_pt *pt){
    printf("\nX:");
    for(int i=0; i < 32; i++){
        printf("%02x", pt->x[i]);
    }
    printf("\nY:");
    for(int i=0; i < 32; i++){
        printf("%02x", pt->y[i]);
    }
    printf("\nT:");
    for(int i=0; i < 32; i++){
        printf("%02x", pt->t[i]);
    }
    printf("\nZ:");
    for(int i=0; i < 32; i++){
        printf("%02x", pt->z[i]);
    }
    printf("\n");
}

void __print_xy(uint8_t *x, uint8_t *y){
    printf("\nX: {");
    for(int i=0; i < 32; i++){
        printf("0x%02x, ", x[i]);
    }
    printf("}\nY: {");
    
    for(int i=0; i < 32; i++){
        printf("0x%02x, ", y[i]);
    }
    printf("}\n");
}

/**
 * @brief Compares to ed25519_pt structs for equality.
 * Adapted from the diffie hellman test in c25519 test_ed25519.c
 * 
 * @param [in] a first point
 * @param [in] b second point
 * @return true in case points are equal
 * @return false otherwise
 */
uint8_t _ed25519_pt_equal(struct ed25519_pt *a, struct ed25519_pt *b)
{
    //__print_ed_point(a);
    //__print_ed_point(b);
    
    uint8_t x1[32], x2[32], y1[32], y2[32] = {0};
    ed25519_unproject(x1, y1, a);
    ed25519_unproject(x2, y2, b);

    f25519_normalize(x1);
    f25519_normalize(x2);
    f25519_normalize(y1);
    f25519_normalize(y2);

    // __print_xy(x1, y1);
    // __print_xy(x2, y2);
    int error = 0;
    //return value of 1 means equality...
    error += f25519_eq(x1,x2);
    error += f25519_eq(y1,y2);

    return (error == 2) ? 0 : -1;
}

/**
 * @brief verifies a Clause-Schnorr signature
 * Computes this s*G = R + c * denom_pub
 */
uint8_t bs_cbs_verify_signature(uint8_t *signer_pub, size_t spub_size,
                                         const uint8_t *msg, size_t msg_size,
                                         const uint8_t *sig, size_t sig_size)
{
    if (sig_size != 64 || spub_size != 32) {
        return -1;
    }
    uint8_t s[32];
    uint8_t R_dash[32];
    uint8_t c_dash[32];
    // sig = (s, R'_b)
    memcpy(s, sig, 32);
    memcpy(R_dash, &sig[32], 32);

    // c'_b = HASH(R'_b, msg)
    uint8_t ret = _calculate_c_dash(R_dash, c_dash, msg, msg_size);
    // puts("c_dash");
    // od_hex_dump(c_dash, 32, 32);
    if (ret != 0) {
        return ret;
    }
    memcpy(R_dash, &sig[32], 32);

    //s*G = R'_b + c'_b * denom_pub
    struct ed25519_pt sG = {0};
    struct ed25519_pt cbDp = {0};
    //sG
    ed25519_smult(&sG, &ed25519_base, s);
    
    //c_b * denom_pub
    struct ed25519_pt Dp = {0};
    _uint8t_to_ed25519pt(signer_pub, &Dp);

    ed25519_smult(&cbDp, &Dp, c_dash);
    //puts("finished parsing pub key");
    // R_b + cbDp
    struct ed25519_pt R_b = {0};
    struct ed25519_pt Rh = {0};
    _uint8t_to_ed25519pt(R_dash, &R_b);

    ed25519_add(&Rh, &cbDp, &R_b);

    // sG == R_b + cbDp
    return _ed25519_pt_equal(&sG, &Rh);
}

uint8_t bs_cbs_unblind_signature(
                    const uint8_t *input, size_t input_length,
                    uint8_t *a0, uint8_t *a1, uint8_t *R0, uint8_t *R1,
                    const uint8_t *output, size_t output_size, size_t *output_length)
{
    if (input_length < 32 + 1) {
        return -1;
    }
    if (output_size < 32*2) {
        return -1;
    }

    //s' = s+ a_b mod L
    uint8_t tmp[32] = {0};
    //memcpy(tmp, &input[1], 32);
    memset((uint8_t *)output, 0, output_size);
    if (input[0] == 0xff) {
        f25519_add(tmp, a1, &input[1]);
        fprime_from_bytes((uint8_t *)output, tmp, 32, ed25519_order_little_endian);
        //fprime_add(tmp, a1, ed25519_order_little_endian);
        memcpy((uint8_t *)&output[32], R1, 32);
    }
    else {
        f25519_add(tmp, a0, &input[1]);
        fprime_from_bytes((uint8_t *)output, tmp, 32, ed25519_order_little_endian);
        // fprime_add(tmp, a0, ed25519_order_little_endian);
        memcpy((uint8_t *)&output[32], R0, 32);
    }
    //memcpy((uint8_t *)output, tmp, 32);
    *output_length = 64;

    return 0;
}
