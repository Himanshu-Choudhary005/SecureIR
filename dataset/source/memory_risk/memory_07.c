int main(void) {
    int values[3] = {10, 20, 30};
    int *ptr = values;

    return *(ptr + 5);
}