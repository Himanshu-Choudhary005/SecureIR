int main(void) {
    int *ptr = 0;
    int *alias = ptr;

    if (alias == 0) {
        return *alias;
    }

    return 0;
}
