#ifndef OSCORE_CONTEXT_PRIMITIVE_H
#define OSCORE_CONTEXT_PRIMITIVE_H

#include <oscore_native/crypto.h>
#include <oscore/helpers.h>

/** @file */

/** @ingroup oscore_contextpair
 *
 * @addtogroup oscore_context_primitive Primitive RAM-only context
 *
 * @brief A pre-derived context implementation that is not persisted
 *
 * This security context describes a very simple setup that is usable with the
 * default OSCORE settings (eg. a 32 long replay window) but otherwise not very
 * sophisticated; in particular, it uses no mechanism that would allow it to
 * recover from an unclean shutdown, and is thus not recommended for any
 * application where a security context needs to persist through outages.
 *
 * Details of this implementation are likely to be later factored out into
 * generically usable components.
 *
 * @{
 */

/** @brief Primitive security context data
 *
 * Data of a simple security context with a 32 long sliding replay window and
 * pre-derived kyes.
 *
 * @warning This context may be stored to persistent media and loaded back from
 * there ONLY IF a) it is made sure that the security context is not in use
 * during or after it is persisted, and b) during loading (before it is
 * actually used), it is made sure that subsequent attempts to load it will
 * fail until it has been stored again.
 */
struct oscore_context_primitive {
    /** AEAD algorithm used with this context */
    oscore_crypto_aeadalg_t aeadalg;
    /** The common IV */
    uint8_t common_iv[OSCORE_CRYPTO_AEAD_IV_MAXLEN];

    /** The sender ID */
    uint8_t sender_id[OSCORE_KEYID_MAXLEN];
    /** The length of @p sender_id */
    size_t sender_id_len;
    /** The sender key */
    uint8_t sender_key[OSCORE_CRYPTO_AEAD_KEY_MAXLEN];
    /** Next sequence number used for sending */
    uint64_t sender_sequence_number;

    /** The recipient ID */
    uint8_t recipient_id[OSCORE_KEYID_MAXLEN];
    /** The length of @p recipient_id */
    size_t recipient_id_len;
    /** The recipient key */
    uint8_t recipient_key[OSCORE_CRYPTO_AEAD_KEY_MAXLEN];
    /** Lowest accepted number in the replay window */
    int64_t replay_window_left_edge;
    /** Bit-mask of packages right of the left edge. If @p
     * replay_window_left_edge is N, then the most significant bit of this
     * represents sequence number N+1, and the least significant bit
     * representsd N+32.
     *
     * You can visualize the state of the window like this, where 1 means
     * 'seen' and 0 means 'still good':
     *
     * ```
     *    -------------+---+-----------------------+---------------
     * ... 1 1 1 1 1 1 | 0 | r_w >> 31 ... r_w & 1 | 0 0 0 0 0 0 0 ...
     *    -------------+---+-----------------------+---------------
     *                   ^
     *          replay_window_left_edge
     * ```
     *
     * */
    uint32_t replay_window;
};

/** @} */

#endif
