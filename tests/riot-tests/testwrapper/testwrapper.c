#include <stdio.h>
#include <assert.h>
#include <stdlib.h>

extern int testmain(int introduce_error);

int main(void)
{
    int result = testmain(0);
    assert(result == 0);
    printf("SUCCESS\n");
    exit(0);
}
