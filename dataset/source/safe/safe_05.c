int main(void) {
    int values[4] = {1, 2, 3, 4};
    int sum = 0;

    for (int i = 0; i < 4; i++) {
        sum += values[i];
    }

    return sum;
}