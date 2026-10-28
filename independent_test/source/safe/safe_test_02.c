int main(void) {
    int values[4] = {2, 4, 6, 8};
    int total = 0;

    for (int i = 0; i < 4; i++) {
        total += values[i];
    }

    return total == 20 ? 0 : 1;
}
