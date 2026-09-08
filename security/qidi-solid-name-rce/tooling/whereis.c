#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
int main(){ void*s=dlsym(RTLD_DEFAULT,"system"); void*p=dlsym(RTLD_DEFAULT,"popen");
  printf("system=%p popen=%p\n",s,p); return 0; }
