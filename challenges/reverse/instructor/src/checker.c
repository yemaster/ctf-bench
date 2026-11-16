#include <stdio.h>
#include <string.h>

#include "secret.h"

/*
 * Two reversible check layers:
 *   1. p[i] = key[perm[i]]                  (byte permutation)
 *   2. target[i] = p[i] ^ p[i-1] ^ f(i)     (adjacent-byte chain)
 * where p[-1] is the fixed seed 0x5a and f(i) = (i*0x1d + 0x33) & 0xff.
 *
 * The data used by both layers lives in license_blob in .rodata.  The public
 * binary is stripped, so the blob has to be located and decoded instead of
 * being read from a symbol table.
 */
static int check_key(const unsigned char *key)
{
    unsigned char p[KEYLEN];
    unsigned char prev = 0x5Au;

    for (unsigned int i = 0; i < license_blob.key_len; i++) {
        unsigned int idx = license_blob.perm[i];
        if (idx >= license_blob.key_len) {
            return 0;
        }
        p[i] = key[idx];
    }

    for (unsigned int i = 0; i < license_blob.key_len; i++) {
        unsigned int v = (unsigned int)p[i] ^ (unsigned int)prev
                       ^ ((i * 0x1dU + 0x33U) & 0xffU);
        if ((v & 0xffU) != license_blob.target[i]) {
            return 0;
        }
        prev = p[i];
    }
    return 1;
}

int main(void)
{
    unsigned char buf[128];
    size_t n;

    printf("license key: ");
    fflush(stdout);
    if (fgets((char *)buf, sizeof buf, stdin) == NULL) {
        return 1;
    }
    buf[strcspn((char *)buf, "\r\n")] = '\0';
    n = strlen((char *)buf);
    if (n != license_blob.key_len) {
        puts("invalid length");
        return 1;
    }
    if (!check_key(buf)) {
        puts("access denied");
        return 1;
    }

    puts("access granted");
    for (unsigned int i = 0; i < license_blob.flag_len; i++) {
        unsigned int k = ((unsigned int)buf[i % license_blob.key_len] * 7u
                        + i * 13u + 0x5au
                        + (unsigned int)buf[(i + 1) % license_blob.key_len])
                       & 0xffu;
        putchar((int)(license_blob.flag_enc[i] ^ k));
    }
    putchar('\n');
    return 0;
}
