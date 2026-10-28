int divide_values(int numerator, int denominator) {
    return numerator / denominator;
}

int main(void) {
    volatile int denominator = 0;
    return divide_values(100, denominator);
}
