#include <stdio.h>
#include <stdlib.h>

/* This function IS the vulnerability, byte-for-byte in spirit. */
static void parse_solid_line(FILE *fp)
{
    char solid_content[256];                       /* fixed stack buffer            */
    int  n = fscanf(fp, " solid %[^\n]", solid_content);  /* %[^\n]: no width -> OOB */
    printf("parsed %d field(s); first 32 bytes: %.32s\n", n, solid_content);
}

int main(int argc, char **argv)
{
    const char *path;
    if (argc > 1) {
        path = argv[1];                            /* study a real .stl if given    */
    } else {
        /* Otherwise synthesize the minimal triggering input: a 20000-char solid    */
        /* name — far past the 256-byte buffer — then one throwaway facet.          */
        path = "F1_essence_input.stl";
        FILE *w = fopen(path, "w");
        fputs("solid ", w);
        for (int i = 0; i < 20000; i++) fputc('A', w);   /* the overflow            */
        fputs("\nfacet normal 0 0 0\n outer loop\n"
              "  vertex 0 0 0\n  vertex 1 0 0\n  vertex 0 1 0\n"
              " endloop\nendfacet\nendsolid\n", w);
        fclose(w);
    }
    FILE *fp = fopen(path, "r");
    if (!fp) { perror("fopen"); return 2; }
    parse_solid_line(fp);                           /* <-- crashes here             */
    fclose(fp);
    puts("(returned normally — no overflow this run)");
    return 0;
}

