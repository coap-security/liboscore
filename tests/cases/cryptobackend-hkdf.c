#include <stdint.h>
#include <string.h>
#include <assert.h>

#include <oscore_native/crypto.h>

const size_t max_output_length = 128;

struct testdata {
    int32_t alg;
    uint8_t *salt;
    size_t salt_len;
    uint8_t *ikm;
    size_t ikm_len;
    uint8_t *info;
    size_t info_len;
    uint8_t *expected;
    size_t expected_len; /* also "to be obtained" length */
};

static struct testdata sha256_data = {
    .alg = 5, /* See https://gitlab.com/oscore/liboscore/-/issues/58 */
    .salt = (uint8_t*)"Hello world",
    .salt_len = 11,
    .ikm = (uint8_t*)"Correct Horse Battery Staple",
    .ikm_len = 28,
    .info = (uint8_t*)"\x80",
    .info_len = 1,
    /* from aiocoap.oscore import *;
     * HKDF(algorithm=hashfunctions[DEFAULT_HASHFUNCTION], salt=b"Hello world",
     * info=b"\x80", length=10).derive(b"Correct Horse Battery Staple")*/
    .expected = (uint8_t*)"\xcc\x80J\xef\xd0\x8c\x8bN\xd9\xcb",
    .expected_len = 10,
};

/* A long salt goes a different code path in the HMAC as it gets hashed once more */
static struct testdata sha256_data_longsalt = {
    .alg = 5,
    .salt = (uint8_t*)"Hello world-------------------this is longer than a single SHA256 block",
    .salt_len = 71,
    .ikm = (uint8_t*)"Correct Horse Battery Staple",
    .ikm_len = 28,
    .info = (uint8_t*)"\x80",
    .info_len = 1,
    .expected = (uint8_t*)"\xbfu\x05J\n\x7fZ\x80\xb1\xcd",
    .expected_len = 10,
};

/* The (for OSCORE applications, exotic) case where several rounds of extraction happen */
static struct testdata sha256_data_longextracted = {
    .alg = 5,
    .salt = (uint8_t*)"Hello world",
    .salt_len = 11,
    .ikm = (uint8_t*)"Correct Horse Battery Staple",
    .ikm_len = 28,
    .info = (uint8_t*)"\x80",
    .info_len = 1,
    /* with manual fixes where Python and C differ in their escaping rules */
    .expected = (uint8_t*)"\xcc\x80J\xef\xd0\x8c\x8bN\xd9\xcb\xf3\xa6\xaa\xbe\xb8\r9\x0b\xa3 \xce~\x13\x92\xa5Z\x87\xf2\xbc\x90Mv\xcdq\xe7\x86\x33\x85\x9b\xdd\x89\xee\x9f\x97h\x97\xf2\xd4s\x1c\xdd\xca\xd1\xe1\xa2n\xfc\xc3\x86_a\x03\xed\x85g\x18\xa7>:*\xfa,\xe6T/\xb2S\x08\x90\x7f",
    .expected_len = 80,
};

int test_with(struct testdata *data, int introduce_error)
{
    uint8_t out_buf[max_output_length];

    assert(data->expected_len <= max_output_length);

    oscore_cryptoerr_t err;

    oscore_crypto_hkdfalg_t alg;

    err = oscore_crypto_hkdf_from_number(&alg, data->alg);
    if (oscore_cryptoerr_is_error(err))
        return 1;

    err = oscore_crypto_hkdf_derive(
            alg,
            data->salt,
            data->salt_len - (introduce_error != 0),
            data->ikm,
            data->ikm_len,
            data->info,
            data->info_len,
            out_buf,
            data->expected_len
            );
    if (oscore_cryptoerr_is_error(err))
        return 2;

    if (memcmp(data->expected, out_buf, data->expected_len) != 0)
        return 3;

    return 0;
}

int testmain(int introduce_error)
{
    int ret = 0;
#ifdef LIBCOSE_HAS_HKDF
    ret = test_with(&sha256_data, introduce_error == 1);
    if (ret != 0)
        return ret;
    /* The current libcose implementation can't do that: */
    (void)sha256_data_longsalt;
    /*
    ret = test_with(&sha256_data_longsalt, introduce_error == 2);
    if (ret != 0)
        return ret;
    */
    ret = test_with(&sha256_data_longextracted, introduce_error > 2);
#else
    (void)introduce_error;
    (void)sha256_data;
    (void)sha256_data_longsalt;
    (void)sha256_data_longextracted;
#endif
    return ret;
}
