#include <limits.h>

int main(void) {
    volatile int value = INT_MIN;

    return -value;
}