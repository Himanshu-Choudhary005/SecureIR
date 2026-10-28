#include <limits.h>

int main(void) {
    volatile int a = INT_MAX;
    volatile int b = 100;

    return a * b;
}