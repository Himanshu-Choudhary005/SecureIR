int main(void) {
    int value = 42;
    int *ptr = &value;

    ptr = 0;

    return *ptr;
}