#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/random.h>

#include "secret.h"

/* Local toy target: no shell, no network.  Reaching win() prints the flag. */
__attribute__((noinline)) static void win(void)
{
    for (size_t i = 0; i < FLAGLEN; i++) {
        unsigned int k = ((unsigned int)i * 13u + 0x37u) & 0xffu;
        putchar((int)(flag_enc[i] ^ k));
    }
    putchar('\n');
    fflush(stdout);
}

static uint32_t rotl32(uint32_t x, unsigned int n)
{
    return (x << n) | (x >> (32u - n));
}

/* Gate 1: the cookie is a fixed, reversible-looking mix of the random value. */
__attribute__((noinline)) static uint32_t mix_challenge(uint32_t x)
{
    x ^= 0x9e3779b9u;
    x = rotl32(x, 13);
    x *= 0x85ebca6bu;
    x ^= x >> 16;
    x *= 0xc2b2ae35u;
    x ^= x >> 13;
    return x ^ 0x1337c0deu;
}

static int random_u32(uint32_t *out)
{
    if (getrandom(out, sizeof *out, 0) == (ssize_t)sizeof *out) {
        return 0;
    }

    FILE *f = fopen("/dev/urandom", "rb");
    if (f == NULL) {
        return -1;
    }
    size_t n = fread(out, 1, sizeof *out, f);
    fclose(f);
    return n == sizeof *out ? 0 : -1;
}

int main(void)
{
    uint32_t challenge = 0;
    uint32_t cookie;

    /* Keep stdio from reading ahead of the raw overflow payload. */
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    if (random_u32(&challenge) != 0) {
        puts("could not obtain randomness");
        return 1;
    }
    cookie = mix_challenge(challenge);

    puts("== local two-gate overflow ==");
    printf("challenge=%08x\n", challenge);
    puts("cookie:");

    char line[64];
    if (fgets(line, sizeof line, stdin) == NULL) {
        puts("input error");
        return 1;
    }
    char *end = NULL;
    errno = 0;
    unsigned long supplied = strtoul(line, &end, 0);
    if (errno != 0 || end == line || supplied > 0xffffffffUL) {
        puts("invalid cookie");
        return 1;
    }
    if ((uint32_t)supplied != cookie) {
        puts("gate 1 failed: wrong cookie");
        return 1;
    }
    puts("gate 1 passed");

    /*
     * Gate 2: a linear overflow has to set both fields at once.  admin must be
     * 0x1337 and auth must be the cookie from gate 1.
     */
    struct {
        char name[32];
        uint32_t admin;
        uint32_t auth;
    } s;

    s.admin = 0;
    s.auth = 0;
    puts("overflow payload:");
    fflush(stdout);
    ssize_t n = read(STDIN_FILENO, s.name, 96);
    (void)n;

    if (s.admin == 0x1337u && s.auth == cookie) {
        puts("admin unlocked");
        win();
    } else {
        printf("gate 2 failed: admin=0x%08x auth=0x%08x\n", s.admin, s.auth);
        puts("need admin=0x1337 and auth=<gate-1 cookie>");
    }
    return 0;
}
