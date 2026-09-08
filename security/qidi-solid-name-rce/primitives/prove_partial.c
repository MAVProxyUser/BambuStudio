// Proof: a partial (low-byte) overwrite redirects an ASLR'd pointer by a known
// delta WITHOUT knowing its full (randomized) value. Run repeatedly with ASLR on;
// the base changes every run, yet the redirect lands on the sentinel every time.
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

// 256-aligned so &arena[k] has low byte == k for k < 256, regardless of ASLR base
static unsigned char arena[0x1000] __attribute__((aligned(256)));

int main(void){
    unsigned origin = 0x34;      // where the pointer legitimately points
    unsigned target = 0x99;      // where the attacker wants it (same 256-block)
    arena[target] = 0xCC;        // sentinel only the redirect can reach

    unsigned char *ptr = &arena[origin];
    uintptr_t base_unknown = (uintptr_t)arena;   // ASLR-randomized; attacker does NOT know this
    printf("run: arena base = %#018lx (randomized)  ptr.low = %#04x\n",
           (unsigned long)base_unknown, (unsigned)((uintptr_t)ptr & 0xff));

    // ---- the attack: overwrite ONLY the low byte of the pointer ----
    ((unsigned char*)&ptr)[0] = (unsigned char)target;   // high 7 bytes untouched

    int hit = (*ptr == 0xCC);
    printf("     ptr.low -> %#04x  deref=%#04x  %s\n",
           target, *ptr, hit ? "HIT (redirected by known delta, base never known)" : "miss");
    return hit ? 0 : 1;
}
