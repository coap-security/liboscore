@page design Design choices

This page explains some design choices taken in libOSCORE.
They are good-to-know general information for library users
(for when they are essential to know, they are linked to explicitly (@FIXME but not yet everywhere)),
and essential to understand for contributors.

Stack allocation sizes
----------------------

This library occasionally asks the application to carry around data in fixed-size structs
rather than giving the minimum size required for this particular case.
For example, stored keys always take up the maximum key size.
This is done not only for simplicity and to avoid dynamic memory management,
but primarily to keep low the risks associated with crypto agility.
Were those data structures dependent on the used algorithm,
then memory exhaustion in production conditions
may be triggered by mere changing of cipher suits
-- which is usually the worst moment to have surprises.

@section design_thread Thread safety and call sequence

The data structures used in this library are not synchronized on their own;
no two functions may operate concurrently on the same message or the same security context simultaneously.
(Conversely, that means that calling libOSCORE functions with disjunct arguments concurrently is fine).

Some groups of functions may require consecutive caling with the same argument.
Unless noted otherwise, this means that the argument needs to have the same value,
and (in case of a pointer) points to unchanged data, recursively --
except of course when the functions in the group change it.
Still, there is no requirement for those functions to happen in the same context,
as long as the group's sequence requirements
and the above requirement on simultaneous calls with identical arguments are met.

In particular -- and with an extension --, this applies to messages:

In the chain of @ref oscore_unprotect_request, @ref oscore_prepare_response and @ref oscore_encrypt_message,
as well as from @ref oscore_prepare_request to @ref oscore_encrypt_message,
the context passed in must not have been modified.
Both chains tolerate other protect and unprotect operations to be interleaved with them
(provided, as always, that no two calls use the context concurrently):
This will result in sequence numbers being changed inside the context,
but not in changes to the key material.

**Additionally**,
the security context's key material needs to stay unmodified available during any writing message operation on the @ref oscore_msg_protected_t.
This is because those invariant parts are read from even when options or payload are written inside the message
(which contains a pointer to the security context).
In practice, that does not change a lot, because the preparation is always followed up by an encryption step
(which again needs the original unmodified security context),
but is required explicitly anyway as a warning incompatible schemes of swapping around keys inside the same security context,
and as a warning against freeing up a security context before all writable messages that use it are finalized.

Asserts
-------

Any `assert` calls are used to verify internal invariants, and to help find the
issue if any such invariant is not upheld. Internal invariants here include the
behavior of the backend implementation. Given we don't get much in terms of
guarantees from C on outside influence, asserts may assume that no outside code
manipulated members declared private in the documentation, and that liboscore's
structs are always used with proper initialization. They may not assume the
validity of any other arguments, especially not sizes passed to liboscore
functions.

Production builds of the library may run with `NDEBUG` set (making all asserts
a no-op), or even in assertion modes where the trigger condition leads to a
branch declared unreachable. Using `assert` is encouraged in places where the
compiler may produce more efficient subsequent code from knowing that the condition is not
hit. (With assertions enabled, the condition is checked and the trailing code
can rely on it to be true. With unreachability indication, the condition is not
checked and the trailing code can still rely. With assertions just elided, the
compiler might create suboptimal code, but probably still better than with
assertions enabled; see [Assertions are Pessimistic, Assumptions are
Optimistic](]https://blog.regehr.org/archives/1096) for a few numbers on how
that may turn out).

An assertion triggering in released code is considered a severe bug (either in
liboscore itself or the backend).

(Using a dedicated `OSCORE_ASSERT` macro for easier overriding is being
considered).

Pointers
--------

The @ref OSCORE_NONNULL macro (expanding to `__attribute__((nonnull))` on GCC)
is used throughout the library to indicate when NULL pointers are inacceptable as arguments.
In practice, this is true for all struct pointers, and not expicitly checked for in the library.

For user-facing operations on memory slices, this library takes a more defensive stance:
Pointers to memory regions of length zero are tolerated by libOSCORE functions to possibly be NULL.
Pointers handed out are never NULL (unless NULL is
explicitly documented as a sentinel value) and always valid, even if expected
to be used zero times.

For example, `oscore_msg_protected_append_option(msg, 5 /* If-None-Match */, NULL, 0)` is accepted,
whereas `oscore_msg_protected_optiter_next` will never put a NULL into its `value` argument as long as it returns true.

(This is to mitigate the widespread unawareness of developers about the
requirements of `memcpy` and similar functions, which require valid pointers. A
careless `append_option(msg, NULL, 0);` could otherwise introduce undefined
behavior).

Functions tolerant of NULL slices are not declared `OSCORE_NONNULL`
(as that would allow the compiler to introduce undefiend behavior when a NULL *is* passewd in),
but still expect other arguments not to be NULL.

@FIXME The addition of an `OSCORE_NONNULL_OPTIN` decorator that makes even those functions nonnull is being considered,
and applications that have good control over their arguments would be encouraged to enable it at build time.
