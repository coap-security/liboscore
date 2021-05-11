#include <string.h>
#include "persistence.h"

#ifdef BOARD_NATIVE

/* The native support of flashpage is not used as that is not persisted */

#include <sys/stat.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

static struct persisted_data *allocated;
static char *filename;

/** Emulating flash storage by creating a persistence.flash (or ${PERSISTENCE_FILENAME}) file.
 *
 * Versioning conflicts are avoided by discarding the file if it's older than the own binary.
 */
bool persistence_init(struct persisted_data **data)
{
    allocated = malloc(sizeof(struct persisted_data));
    *data = allocated;

    filename = getenv("PERSISTENCE_FILENAME");
    if (filename == NULL)
        filename = "persistence.flash";

    struct stat own_binary;
    struct stat old_file;

    if (stat("/proc/self/exe", &own_binary)) {
        perror("Failed to stat own file, discarding any persistence data");
        return false;
    }
    if (stat(filename, &old_file)) {
        // Absence of the file will not be announced, it's not an error but expected
        if (errno != ENOENT)
            perror("Failed to stat persistence file, discarding any persistence data");
        return false;
    }

    if (own_binary.st_mtime > old_file.st_mtime) {
        fprintf(stderr, "Persistence fileis older than own binary, discarding persisted state on first write.\n");
        return false;
    }

    int f = open(filename, O_RDONLY);
    if (f <= 0) {
        perror("Failed to open persistence file");
        return false;
    }

    ssize_t bytesread = read(f, allocated, sizeof(struct persisted_data));
    if (bytesread != sizeof(struct persisted_data)) {
        // It's small enough that it's very very very unlikely that we'd need
        // to keep reading after a short read.
        fprintf(stderr, "Failed to read complete persisted data from file.\n");
        return false;
    }

    return true;
}

/** Write data from allocated memory to the file.
 *
 * Like the below flash-based implementation, this will not do any tempfile
 * stuff to avoid losing data; if the program is interrupted right while it's
 * writing, bad luck.
 */
void persistence_commit(void)
{
    int f = open(filename, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
    if (f <= 0) {
        perror("Failed to open persistence file; aborting");
        abort();
    }

    if (write(f, allocated, sizeof(struct persisted_data)) != sizeof(struct persisted_data)) {
        fprintf(stderr, "Failed to write all data to persistence file; aborting.\n");
        abort();
    }

    if (fsync(f) != 0) {
        perror("Failed to sync persistence data; aborting");
        abort();
    }

    if (close(f) != 0) {
        perror("Failed to close persistence file)");
        abort();
    }
}

#else // non-native boards

#include <periph/flashpage.h>

// Don't access directly, as the compiler would infer from its const-ness that
// its null content may be propagated
static const uint8_t backing_memory[FLASHPAGE_SIZE] __attribute__((aligned(FLASHPAGE_SIZE))) = {0};

// The RAM that's read from the flashpage, and where to data is written to
// before it is flashed.
uint8_t flashpage_buffer[FLASHPAGE_SIZE] __attribute__((aligned(FLASHPAGE_WRITE_BLOCK_ALIGNMENT))) = {0};

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

#endif
