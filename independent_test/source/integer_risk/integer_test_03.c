int main(void) {
    volatile unsigned int value = 1U;
    volatile unsigned int shift = 32U;
    return value << shift;
}
