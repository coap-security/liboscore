#include <oscore/contextpair.h>

oscore_crypto_aeadalg_t oscore_context_get_aeadalg(const oscore_context_t *secctx)
{
    return 24;
}

void oscore_context_get_kid(
        const oscore_context_t *secctx,
        enum oscore_context_role role,
        uint8_t **kid,
        size_t *kid_len
        )
{
    static uint8_t *s = (uint8_t*) "";
    *kid = s;
    *kid_len = 0;
}

const uint8_t *oscore_context_get_commoniv(const oscore_context_t *secctx)
{
    // 12 bytes ChaCha
    static uint8_t *c = (uint8_t*) "d\xf0\xbd" "1MK\xe0<'\x0c+\x1c";
    return c;
}
const uint8_t *oscore_context_get_key(
        const oscore_context_t *secctx,
        enum oscore_context_role role
        )
{
    // ChaCha key
    static uint8_t *k = (uint8_t*) "\xd5" "0\x1e\xb1\x8d\x06xI\x95\x08\x93\xba*\xc8\x91" "A|\x89\xae\t\xdfJ8U\xaa\x00\n\xc9\xff\xf3\x87Q";
    return k;
}
