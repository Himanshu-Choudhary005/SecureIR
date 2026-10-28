int main(void) {
    int values[5] = {10, 20, 30, 40, 50};
    volatile int index = 7;

    return values[index];
}