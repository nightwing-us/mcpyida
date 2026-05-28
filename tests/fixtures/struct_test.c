/*
 * Test binary for struct type operations.
 *
 * Known properties for automated testing:
 * - Structs: Config (16 bytes), Point (8 bytes)
 * - Functions: init_config, process_config, use_point, main
 * - Local variables in process_config:
 *   - cfg (Config*) — pointer to struct passed as param
 *   - total (int) — computed from struct fields
 *   - p (Point) — local struct on stack
 * - Local variables in use_point:
 *   - pt (Point*) — pointer param
 *   - sum (int) — computed from struct fields
 *
 * Build: gcc -g -O0 -o struct_test.elf struct_test.c -no-pie
 *   -g for debug info (struct definitions preserved)
 *   -O0 to prevent optimizing away locals
 *   -no-pie for stable addresses
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int flag;
    int count;
    char name[8];
} Config;

typedef struct {
    int x;
    int y;
} Point;

/* Uses a Config pointer — decompiler should show Config* param */
int process_config(Config *cfg) {
    int total = cfg->flag + cfg->count;
    Point p;
    p.x = total;
    p.y = total * 2;
    printf("Config: %s flag=%d count=%d total=%d\n",
           cfg->name, cfg->flag, cfg->count, total);
    printf("Point: (%d, %d)\n", p.x, p.y);
    return p.x + p.y;
}

/* Uses a Point pointer */
int use_point(Point *pt) {
    int sum = pt->x + pt->y;
    printf("Point sum: %d\n", sum);
    return sum;
}

/* Initializes a Config on the stack */
Config *init_config(void) {
    Config *cfg = (Config *)malloc(sizeof(Config));
    if (!cfg) return NULL;
    cfg->flag = 1;
    cfg->count = 42;
    strncpy(cfg->name, "test", sizeof(cfg->name) - 1);
    cfg->name[sizeof(cfg->name) - 1] = '\0';
    return cfg;
}

int main(void) {
    Config *cfg = init_config();
    if (!cfg) return 1;

    int result = process_config(cfg);

    Point pt;
    pt.x = result;
    pt.y = result / 2;
    int final_sum = use_point(&pt);

    printf("Final: %d\n", final_sum);
    free(cfg);
    return 0;
}
