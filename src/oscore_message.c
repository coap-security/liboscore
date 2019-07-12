typedef enum {
    /** Place this in Class E unconditionally, and refuse to decrypt messages
     * with this as an outer option
     *
     * This includes all Class E+U options like the Block options, as they need
     * to be resolved (and removed) by the underlying CoAP library.
     * */
    ONLY_E,
    // We could also have a "ONLY_E_IGNORE_OUTER" where the iterator silently
    // disregards outer options.

    /** Place this in Class U unconditionally. Inner options of this type are
     * still accepted, and both the outer and inner values are reported when
     * iterating over options. */
    PRIMARILY_U,
    /** Place this in Class I unconditionally, and (by design of the AAD)
     * refuse to decrypt messages where they were altered. Inner options of
     * this type are still accepted, and both the outer and inner values are
     * reported when iterating over options. */
    PRIMARILY_I,

    // We could have an "ONLY_[UI]_IGNORE_INNER", but I don't see where that'd
    // make sense.

    /** None of the slotted behaviors fits, this option needs special care (eg.
     * Observe) */
    HARDCODED,

} option_behavior;

