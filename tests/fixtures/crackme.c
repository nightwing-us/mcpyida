/* tests/fixtures/crackme.c
 *
 * Simple test binary with known properties:
 * - Functions: main, check_password
 * - Strings: "secret123", "Correct!\n", "Wrong!\n", "Usage: %s <password>\n"
 * - Imports: printf, strcmp
 * - Xrefs: main -> check_password -> strcmp
 * - Segments: .text, .data/.rodata
 *
 * Build: gcc -o crackme.elf crackme.c -no-pie
 */
#include <stdio.h>
#include <string.h>

int check_password(const char *input) {
    return strcmp(input, "secret123") == 0;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <password>\n", argv[0]);
        return 1;
    }
    if (check_password(argv[1])) {
        printf("Correct!\n");
        return 0;
    }
    printf("Wrong!\n");
    return 1;
}
