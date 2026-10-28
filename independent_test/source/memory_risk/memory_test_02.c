int *make_pointer(void) {
    int local_value = 100;
    return &local_value;
}

int main(void) {
    int *ptr = make_pointer();
    return *ptr;
}
