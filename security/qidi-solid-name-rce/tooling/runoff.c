#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
extern char **environ;
#ifndef _POSIX_SPAWN_DISABLE_ASLR
#define _POSIX_SPAWN_DISABLE_ASLR 0x0100
#endif
int main(int argc, char **argv){
    if (argc < 2){ fprintf(stderr,"usage: runoff prog [args...]\n"); return 2; }
    posix_spawnattr_t a; posix_spawnattr_init(&a);
    posix_spawnattr_setflags(&a, _POSIX_SPAWN_DISABLE_ASLR | POSIX_SPAWN_SETEXEC);
    posix_spawn(NULL, argv[1], NULL, &a, &argv[1], environ);
    perror("posix_spawn"); return 1;   // only if SETEXEC failed
}
