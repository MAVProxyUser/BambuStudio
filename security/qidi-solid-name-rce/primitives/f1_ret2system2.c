#include <stdio.h>
// Faithful F1 bug: unbounded ASCII-STL "solid" name into a 256 stack buffer.
// Returns the buffer so x0 = &buf at the epilogue (the command string lives there).
char *parse_solid(FILE *fp){
    char solid_content[256];
    fscanf(fp, " solid %[^\n]", solid_content);   // the overflow
    return solid_content + 0x140; // x0 above system frame
}
int main(int argc, char **argv){
    if(argc<2){ fprintf(stderr,"usage: %s file.stl\n",argv[0]); return 2; }
    FILE *fp=fopen(argv[1],"r"); if(!fp){perror("fopen");return 2;}
    parse_solid(fp);
    puts("(returned normally)");
    return 0;
}
