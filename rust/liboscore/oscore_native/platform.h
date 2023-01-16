/** To avoid depending on the libc, these are provided in
 * platform.rs. As their signatures are so simple, we're not going
 * through a round of cbindgen for them. */

#include <stdbool.h>
#include <stddef.h>

void assert(bool expression);
void abort(void);
void *memcpy(void *dest, const void *src, size_t n);
int memcmp(const void *s1, const void *s2, size_t n);
void *memset(void *s, int c, size_t n);
