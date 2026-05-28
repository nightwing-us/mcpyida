/* tests/fixtures/typed_fixture.c
 *
 * Test binary with known types and debug info:
 * - Structs: Point (8 bytes), Wrapper (28 bytes)
 * - Globals: g_point, g_wrapper, g_numbers, g_message
 * - Functions: main -> use_wrapper -> sum_point
 * - Call graph: main -> use_wrapper -> sum_point
 *
 * Build: gcc -g -o typed_fixture.elf typed_fixture.c -no-pie
 */
#include <stdint.h>
#include <stdio.h>

typedef struct {
    int32_t x;
    int32_t y;
} Point;

typedef struct {
    Point pt;
    uint32_t magic;
    char name[16];
} Wrapper;

Point g_point = {10, 20};
Wrapper g_wrapper = {{1, 2}, 0xDEADBEEF, "test"};
int32_t g_numbers[4] = {1, 2, 3, 4};
const char *g_message = "hello from fixture";

int sum_point(Point *p) {
    return p->x + p->y;
}

int use_wrapper(Wrapper *w) {
    int s = sum_point(&w->pt);
    printf("sum=%d magic=0x%x name=%s\n", s, w->magic, w->name);
    return s + (int)w->magic;
}

int main(void) {
    return use_wrapper(&g_wrapper);
}
