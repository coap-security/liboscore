#include "plugtest-server.h"
#include "demo-server.h"

/** Resources used by the oscore_handler dispatcher
 *
 * As a `struct dispatcher_choice` is built from this, the items in here must
 * follow its constraints; that is most easily achieved by sorting them by path
 * (for an arbitrary order on strings).
 */

/* From the plug test */

RESOURCE(hello, 3, PATH("oscore", "hello", "1"), hello_parse, hello_build, struct hello_state)
RESOURCE(hello2, 3, PATH("oscore", "hello", "2"), hello2_parse, hello2_build, struct hello_state)
RESOURCE(hello3, 3, PATH("oscore", "hello", "3"), hello3_parse, hello3_build, struct hello_state)
RESOURCE(hello6, 3, PATH("oscore", "hello", "6"), hello6_parse, hello6_build, struct hello_state)
RESOURCE(hello7, 3, PATH("oscore", "hello", "7"), hello7_parse, hello7_build, struct hello_state)
RESOURCE(observe1, 2, PATH("oscore", "observe1"), observe1_parse, observe1_build, struct hello_state)
RESOURCE(delete, 2, PATH("oscore", "test"), delete_parse, delete_build, struct hello_state)

/* From the demo server */

RESOURCE(light, 1, PATH("light"), light_parse, light_build, uint16_t)
RESOURCE(sensordata, 1, PATH("sensordata"), sensordata_parse, sensordata_build, struct sensordata_blockopt)
