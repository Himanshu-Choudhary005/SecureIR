#include <limits.h>

int main(void) {
    volatile int value = INT_MAX;
    volatile int increment = 1;

    int result = value + increment;

    return result;
}