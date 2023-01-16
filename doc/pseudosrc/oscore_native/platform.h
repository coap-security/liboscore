/** @file */

#include <stdbool.h>
#include <stddef.h>

/** @ingroup oscore_native_types
 *  @addtogroup oscore_native_platform_functions Native platform provided functions
 *
 *  These functions are typically provided by the system's libc (these are
 *  selected when using the `libc` backend). libOSCORE supports custom
 *  implementations for platforms that have no libc (eg. wasm32 without
 *  emscripten). All uses of these functions go through the
 *  `oscore_native/platform.h` include.
 *
 *  Platform specific headers that are part of a freestanding C implementations
 *  (eg. `stddef.h`, `stdint.h` and `stdbool.h`) are still used directly.
 *
 *  @{ */

/** Abort the process if the expression is false
 *
 * See @ref design for how this is used inside libOSCORE.
 */
void assert(bool expression);

/** Abort the process
 *
 * See @ref design for how this is used inside libOSCORE.
 */
void abort(void);

/** Copy non-overlapping memory from src to dest, returning dest */
void *memcpy(void *dest, const void *src, size_t n);

/** Compare memory areas, returning the sign of the difference between the
 * first pair of unsigned char values */
int memcmp(const void *s1, const void *s2, size_t n);

/** Fill an area of memory with a given char, returning the area
 * pointer */
void *memset(void *s, int c, size_t n);

/** @} */
