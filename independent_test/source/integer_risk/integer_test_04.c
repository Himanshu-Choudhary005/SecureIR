int main(void) {
    volatile int numerator = -2147483647 - 1;
    volatile int denominator = -1;
    return numerator / denominator;
}
