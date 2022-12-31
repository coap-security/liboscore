#ifndef OSCORE_PROTECTION_H
#define OSCORE_PROTECTION_H

#include <stdint.h>

#include <oscore_native/message.h>
#include <oscore/message.h>
#include <oscore/helpers.h>
#include <oscore/contextpair.h>

/** @file */

/** @ingroup oscore_api
 *
 * @addtogroup oscore_protection OSCORE protection API
 *
 * @brief API for creating OSCORE messages from CoAP messages
 *
 * These functions create OSCORE messages (that can be used with the @ref
 * oscore_msg) from native messages (that were used with the @ref
 * oscore_native_msg). On reception, they decrypt the message and make it
 * viewable as a @ref oscore_msg_protected_t; on transmission, the outgoing
 * message buffer is wrapped in a @ref oscore_msg_protected_t so that options
 * can be written to it in the right places, and eventually encrypted before
 * transmission.
 *
 * @anchor oscore_protection_finish
 *
 * @note
 * Several functions that finish off a OSCORE message return the native message
 * that was originally passed in.
 *
 * @note
 * Those are returned for the benefit of applications that would not otherwise
 * hold a reference to the encapsulated message. Applications may rely on those
 * to to be the same (but, usually, internally modified) message that was
 * passed in when the @ref oscore_msg_protected_t was created, and can thus
 * ignore those return values.
 *
 * @{
 */

/** @brief Pre-parsed OSCORE header information
 *
 * This type contains the information extracted from the OSCORE header.
 * Instances may only live as long as the message they belong to does and is
 * not moved in memory.
 *
 * When such a type was created, it was already verified that it is well-formed
 * and contains no unknown extension bits.
 *
 * Currently, it is a simple fat pointer, but that is subject to change as an
 * implementation detail.
 *
 */
typedef struct {
    /** @brief IV length
     *
     * This is exactly the `n` of the flags.
     *
     * @private
     * */
    uint8_t partial_iv_len;
    /** @brief Length of the KID context
     *
     * This is only initialized if @p kid_context is not NULL.
     *
     * In the struct's sequence, this is swapped with @p partial_iv with
     * respect to the occurrence on the wire to reduce padding introduced by
     * C's requirement of alignment and member sequence preservation.
     *
     * @private
     */
    uint8_t kid_context_len;
    /** @brief Pointer to the partial IV
     *
     * The valid size after the pointer is determined by the `n` bits of @p
     * flags, and is NULL iff `n = 0` in the flags.
     *
     * @private
     * */
    const uint8_t *partial_iv;
    /** @brief KID context
     *
     * The valid size after the pointer is determined by `s`. This points to
     * NULL iff `h=0` in the flags.
     *
     * @private */
    const uint8_t *kid_context;
    /** @brief KID
     *
     * The valid size after the pointer is determined by `kid_len`. This points
     * to NULL iff `k=0` in the flags.
     *
     * @private */
    const uint8_t *kid;
    /** @brief Length of the KID
     *
     * This is only set if @p kid is not NULL.
     *
     * @private */
    size_t kid_len;
} oscore_oscoreoption_t;

/** @brief Parse an OSCORE option
 *
 * This reads a CoAP OSCORE option and creates an @ref oscore_oscoreoption_t
 * from it if it is well-formed and has no unknown or invalid fields.
 *
 * Typically this is used at initial processing of a message when its options
 * are first iterated over, and an OSCORE option is encountered.
 *
 * The @p input provided needs to be valid for as long as the resulting @p out
 * is used. In the typical case, this is provided by the @ref
 * oscore_specific_native_requirements.
 *
 * @param[out] out Uninitialized memory to parse the option into
 * @param[in] input OSCORE option encoded according to OSCORE Header Compression
 * @param[in] input_len Length of the encoded OSCORE option
 * @return true if the option could be parsed entirely.
 */
OSCORE_NONNULL
bool oscore_oscoreoption_parse(oscore_oscoreoption_t *out, const uint8_t *input, size_t input_len);

/** @brief Clone a request @ref oscore_requestid_t
 *
 * @param[out] dest Previously uninitialized memory location of the destination
 * @param[in] src Memory location of a source
 *
 * This copies message correlation data, but sets the new copy's "may reuse the
 * partial IV" flag to false, thus ensuring that at most one response is sent
 * using the client-provided nonce.
 */
OSCORE_NONNULL
void oscore_requestid_clone(oscore_requestid_t *dest, oscore_requestid_t *src);

/** @brief Results of unprotect request operations
 *
 * Users of the library should never check for identity to unsuccessful values,
 * as those may be extended in future to provide better debugging.
 * */
enum oscore_unprotect_request_result {
    /** Unprotection succeeded, and the Partial IV was not seen before */
    OSCORE_UNPROTECT_REQUEST_OK,
    /** Unprotection succeeded, but was a replay (possibly a second
     * transmission, when the underlying CoAP library does not perform
     * deduplication), or it could not be determined whehter it could have been
     * a replay or not. */
    OSCORE_UNPROTECT_REQUEST_DUPLICATE,
    /** Unprotection failed (because the message was tampered with, or
     * decryption was attempted with the wrong security context) */
    OSCORE_UNPROTECT_REQUEST_INVALID
};

/** @brief Request message decryption
 *
 * Unprotect a request message with a given security context.
 *
 * @param[in] protected A received request message
 * @param[out] unprotected A pre-allocated, uninitialized @ref oscore_msg_protected_t that will be made available on success
 * @param[in] header An @ref oscore_oscoreoption_t extracted from `message`
 * @param[inout] secctx The security context with which to decrypt (and by which to validate) the message
 * @param[out] request_id An uninitialized request ID that can later be used to protect the response
 *
 * @return OSCORE_UNPROTECT_REQUEST_OK if decryption and authentication
 * succeeded and the request could be verified and replay protection succeeded,
 * OSCORE_UNPROTECT_REQUEST_DUPLICATE if decryption and authentication
 * succeeded byt the replay protection indicates it could be a replay (or
 * replay protection is not set up correctly yet), and any other if
 * decryption/authentication failed.
 *
 * The OK and DUPLICATE results both count as successful in terms of
 * initialization: A message will be available in `unprotected`, but in the
 * duplicate case must only be processed further if it is safe (in the
 * CoAP/REST sense, ie. side effect free; currently that's GET and FETCH
 * requests).
 *
 * @note The result enum is used to reduce the risk of API users inadvertedly
 * processing replays. The information about whether a request was (possibly) a
 * duplicate or not is also encoded in request_id's "is first use" property,
 * but having a dedicated return value forces users to take a conscious
 * decision.
 *
 * When this function is followed up by a @ref oscore_prepare_response (as it
 * usually is), the same @ref design_thread "unmodified security context" and
 * @p request_id must be used in that subsequent call.
 */
OSCORE_NONNULL
enum oscore_unprotect_request_result oscore_unprotect_request(
        oscore_msg_native_t protected,
        oscore_msg_protected_t *unprotected,
        const oscore_oscoreoption_t *header,
        oscore_context_t *secctx,
        oscore_requestid_t *request_id
        );

/** @brief Results of unprotect response operations
 *
 * This is different from @ref oscore_unprotect_request_result in that no
 * replay protection is active in response processing, so there is no
 * "_DUPLICATE" outcome.
 *
 * Users of the library should never check for identity to unsuccessful values,
 * as those may be extended in future to provide better debugging.
 * */
enum oscore_unprotect_response_result {
    /** Unprotection succeeded */
    OSCORE_UNPROTECT_RESPONSE_OK,
    /** Unprotection failed (because the message was tampered with, or
     * decryption was attempted with the wrong security context) */
    OSCORE_UNPROTECT_RESPONSE_INVALID
};

/** @brief Response message decryption
 *
 * Unprotect a message with a given security context.
 *
 * @param[in] protected A received message
 * @param[out] unprotected A pre-allocated, uninitialized @ref oscore_msg_protected_t that will be made available on success
 * @param[in] header An @ref oscore_oscoreoption_t extracted from `message`
 * @param[inout] secctx The security context with which to decrypt (and by which to validate) the message
 * @param[in] request_id Matching information from the protect step of the request message.
 *
 * @return OSCORE_UNPROTECT_OK if decryption and authentication succeeded,
 * or any other if decryption/authentication failed.
 *
 */
enum oscore_unprotect_response_result oscore_unprotect_response(
        oscore_msg_native_t protected,
        oscore_msg_protected_t *unprotected,
        const oscore_oscoreoption_t *header,
        oscore_context_t *secctx,
        oscore_requestid_t *request_id
        );

/** @brief Free a native message from a protected message's control
 *
 * This relinquishes an @ref oscore_msg_protected_t's hold on a native message
 * after it has been used in an unprotect operation.
 *
 * The message can not be expected to have meaningful content any more (in
 * practice, it will contain its outer options as well as a payload consisting
 * of the OSCORE plaintext).
 *
 * This function's counterpart in protect operations is @ref oscore_encrypt_message.
 *
 * The result @ref oscore_protection_finish "may be discarded".
 *
 */
oscore_msg_native_t oscore_release_unprotected(
        oscore_msg_protected_t *unprotected
        );

/** @brief Results of message encryption preparation
 *
 * Users of the library should never check for identity to unsuccessful values,
 * as those may be extended in future to provide better debugging.
 * */
enum oscore_prepare_result {
    /** Preparation successful */
    OSCORE_PREPARE_OK,
    /** The security context can not provide protection for this message */
    // There may be a future distinction between temporary ("Can't send yet,
    // flash write not completed yet") and permanent failures
    OSCORE_PREPARE_SECCTX_UNAVAILABLE,
};

/** @brief Response message preparation
 *
 * Start building a message for encryption with a given security context.
 *
 * @param[in] protected An allocated message into which the operations on @p unprotected can write
 * @param[in] unprotected A pre-allocated, uninititialized @ref oscore_msg_protected_t that the message can be written to
 * @param[inout] secctx A security context used to protect the message, which a sequence number will be taken from on demand
 * @param[inout] request_id The request ID of the incoming message. This is marked for input and output because creating the response re-using the request ID's sequence number will clear its "first use" property.
 *
 * @return OSCORE_PREPARE_OK if all information is available to continue, or
 * any other if not.
 *
 * @attention The @p secctx passed in here must be the same as in the preceding
 * @ref oscore_unprotect_request call, and may only be used to protect and
 * unprotect other messages (and not altered in any other way) until the
 * subsequent @ref oscore_encrypt_message function has been called. See
 * @ref design_thread for more details.
 */
OSCORE_NONNULL
enum oscore_prepare_result oscore_prepare_response(
        oscore_msg_native_t protected,
        oscore_msg_protected_t *unprotected,
        oscore_context_t *secctx,
        oscore_requestid_t *request_id
        );

/** @brief Request message preparation
 *
 * Start building a message for encryption with a given security context.
 *
 * @param[in] protected An allocated message into which the operations on @p unprotected can write
 * @param[in] unprotected A pre-allocated, uninititialized @ref oscore_msg_protected_t that the message can be written to
 * @param[inout] secctx A security context used to protect the message, which a sequence number will be taken from on demand
 * @param[out] request_id The request ID created in the process for this exchange, and is later used to unprotect the response.
 *
 * @return OSCORE_PREPARE_OK if all information is available to continue, or
 * any other if not.
 *
 * @attention The @p secctx passed in here may only be used to protect and
 * unprotect other messages (and not altered in any other way) until the
 * subsequent @ref oscore_encrypt_message function has been called.
 * See @ref design_thread for more details.
 */
OSCORE_NONNULL
enum oscore_prepare_result oscore_prepare_request(
        oscore_msg_native_t protected,
        oscore_msg_protected_t *unprotected,
        oscore_context_t *secctx,
        oscore_requestid_t *request_id
        );

/** @brief Results of message encryption
 *
 * Users of the library should never check for identity to unsuccessful values,
 * as those may be extended in future to provide better debugging.
 * */
enum oscore_finish_result {
    /** Encryption successful */
    OSCORE_FINISH_OK,
    /** The space allocated for the message was insufficient for adding the
     * AEAD tag. This error showing indicaes a programming error in one of the
     * previously executed OSCORE message manipulation functions, as those
     * should fail rather than use data allocated for the tag. */
    OSCORE_FINISH_ERROR_SIZE,
    /** The cryptography backend produced an error while encrypting the
     * message. This may not even be possible in some implementations, but can,
     * for example, indicate that the backend needs to perform memory
     * allocation for creating a contiguous AAD, and failed in that.
     */
    OSCORE_FINISH_ERROR_CRYPTO,
};


/** @brief Encrypt a previously prepared and populated message
 *
 * This encrypts a that has been initiallized by @ref oscore_prepare_request or
 * @ref oscore_prepare_response. The @ref oscore_msg_protected_trim_payload
 * function must be called on the message before it is encrypted (which needs
 * to happen anyway because the allocated message size in practically all cases
 * exceeds the required number of bytes on the wire, eg. because the length of
 * the OSCORE option depends on the sequence number).
 *
 * @param[inout] unprotected The message that has been built. This is described as "inout" because while the struct is coming in initialized, it should be considered uninitialized after this function. It is a usage error (that is caught unless assertions are disabled) to use the same struct for anything else that assumes that it is initialized.
 * @param[out] protected The native message that was passed in in the protection step, which now contains the ciphertext.
 * @return OSCORE_FINISH_OK if all steps succeeded, any other value otherwise.
 *
 * @attention Be sure to check the success value of this before sending @p
 * protected. That message may be easily in a state in which the CoAP backend
 * would accept it for sending, but contains unencrypted data. Not setting that
 * field was considered as an API alternative (that would be slightly safer to
 * use as the user has chances of getting NULL pointers back that the sending
 * CoAP library would hopefully refuse loudly), but eventually discarded
 * because of the risks of whole-program optimizing compilers reinstating
 * turning that undefined behavior into the present behavior (without the
 * benefit of this warning to the user).
 *
 * Even when this function returns unsuccessfully, the underlying native
 * message is returned in @p protected and can be freed. Likewise, either way,
 * the @p unprotected can not be used after this call any more.
 *
 * The value returned in @p protected
 * @ref oscore_protection_finish "may be discarded"
 * as it's the same originally passed in (but still needs to be a valid
 * pointer).
 */
OSCORE_NONNULL
enum oscore_finish_result oscore_encrypt_message(
        oscore_msg_protected_t *unprotected,
        oscore_msg_native_t *protected
        );

/** @} */

#endif
