int *get_pointer(void) {
    int value = 42;

    return &value;
}

int main(void) {
    int *ptr = get_pointer();

    return *ptr;
}