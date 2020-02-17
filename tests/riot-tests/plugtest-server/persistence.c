#include <string.h>
#include <periph/flashpage.h>
#include "persistence.h"

// Don't access directly, as the compiler would infer from its const-ness that
// its null content may be propagated
static const uint8_t backing_memory[FLASHPAGE_SIZE] __attribute__((aligned(FLASHPAGE_SIZE))) = {0};

// The RAM that's read from the flashpage, and where to data is written to
// before it is flashed.
uint8_t flashpage_buffer[FLASHPAGE_SIZE] __attribute__((aligned(FLASHPAGE_RAW_ALIGNMENT))) = {0};

static int flashpage;

bool persistence_init(struct persisted_data **data)
{
    assert(2 * sizeof(struct persisted_data) <= FLASHPAGE_SIZE);

    flashpage = flashpage_page((void*)backing_memory);

    flashpage_read(flashpage, flashpage_buffer);

    *data = (void*)flashpage_buffer;

    // Simpler than checksumming: data stored twice, second is inverted; this
    // doesn't happen by accident but is way easier than starting any
    // checksumming here.
    for (unsigned int i = 0; i < sizeof(struct persisted_data); ++i)
        if (flashpage_buffer[i] != 0xff - flashpage_buffer[i + sizeof(struct persisted_data)])
            return false;
    return true;
}

void persistence_commit(void)
{
    // Update the inverted copy, which is used instead of checksumming
    for (unsigned int i = 0; i < sizeof(struct persisted_data); ++i)
        flashpage_buffer[i + sizeof(struct persisted_data)] = 0xff - flashpage_buffer[i];

    int ok = flashpage_write_and_verify(flashpage, flashpage_buffer);
    assert(ok == FLASHPAGE_OK);
    // Guard against NDEBUG
    while (ok != FLASHPAGE_OK);

}
