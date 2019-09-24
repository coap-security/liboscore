#!/bin/sh

set -e

timeout ${RIOT_TEST_TIMEOUT:-10} make term | tee /dev/stderr | grep '^SUCCESS$' >/dev/null
