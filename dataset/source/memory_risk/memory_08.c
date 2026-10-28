int main(void) {
    int values[4] = {10, 20, 30, 40};
    volatile int index = 8;

    return values[index];
}