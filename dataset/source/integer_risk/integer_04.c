#include <limits.h>

int main(void) {
    volatile int a = INT_MIN;
    volatile int b = 1;

    return a - b;
}