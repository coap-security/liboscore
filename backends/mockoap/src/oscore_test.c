#include <oscore_native/message.h>

#include <stdlib.h>

#define MOCKOAP_DEFAULT_SIZE 1024

oscore_msg_native_t oscore_test_msg_create(void)
{
    uint8_t *payload = malloc(MOCKOAP_DEFAULT_SIZE);
    if (payload == NULL) {
        return NULL;
    }

    struct mock_message *ret = malloc(sizeof(struct mock_message));
    if (ret != NULL) {
        ret->code = 0;
        ret->payload = payload;
        ret->payload_len = MOCKOAP_DEFAULT_SIZE;
        ret->option = NULL;
    }
    return ret;
}

void oscore_test_msg_destroy(oscore_msg_native_t message)
{
    if (message == NULL) {
        return;
    }

    free(message->payload);
    struct mock_opt *next = message->option;
    while (next != NULL) {
        struct mock_opt *current = next;
        next = current->next;
        free(current->data);
        free(current);
    }

    free(message);
}
