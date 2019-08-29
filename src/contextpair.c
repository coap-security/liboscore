#include <oscore/contextpair.h>

oscore_crypto_aeadalg_t oscore_context_get_aeadalg(const oscore_context_t *secctx)
{
    return 10;
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
    static uint8_t *c = (uint8_t*) "\x46\x22\xd4\xdd\x6d\x94\x41\x68\xee\xfb\x54\x98\x7c";
    return c;
}
const uint8_t *oscore_context_get_key(
        const oscore_context_t *secctx,
        enum oscore_context_role role
        )
{
    static uint8_t *k = (uint8_t*) "\xf0\x91\x0e\xd7\x29\x5e\x6a\xd4\xb5\x4f\xc7\x93\x15\x43\x02\xff";
    return k;
}
