typedef unsigned long long ull;
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <mach-o/dyld.h>
#include <sys/ucontext.h>
static volatile int inhandler=0;
static FILE*F;
static void tryread(const char*tag, ull addr){
    if(inhandler>1){ return; }         // a nested fault happened; skip
    inhandler=2;                        // mark: about to touch memory
    unsigned char*p=(unsigned char*)addr; char buf[97]; int ok=1;
    for(int i=0;i<32;i++){ buf[i*2]="0123456789abcdef"[p[i]>>4]; buf[i*2+1]="0123456789abcdef"[p[i]&15]; }
    buf[64]=0;
    fprintf(F,"  %s @ %#llx: %s |",tag,addr,buf);
    for(int i=0;i<32;i++){unsigned char c=p[i]; fputc((c>=32&&c<127)?c:'.',F);} fprintf(F,"|\n");
    (void)ok; inhandler=1;
}
static void h(int sig, siginfo_t*info, void*uctx){
    if(inhandler){ _exit(124); }        // re-entered from a bad tryread -> bail
    inhandler=1;
    ucontext_t*uc=(ucontext_t*)uctx; _STRUCT_ARM_THREAD_STATE64*ss=&uc->uc_mcontext->__ss;
    F=fopen("/tmp/qidi_regs.txt","w");
    long slide=_dyld_get_image_vmaddr_slide(0);
    fprintf(F,"slide=%#lx main_base=%#llx\n",slide,(ull)_dyld_get_image_header(0));
    fprintf(F,"signal %d fault %p pc=%#llx (file+%#llx) sp=%#llx fp=%#llx lr=%#llx (file+%#llx)\n",
        sig,info->si_addr,(ull)ss->__pc,(ull)ss->__pc-slide,(ull)ss->__sp,(ull)ss->__fp,
        (ull)ss->__lr,(ull)ss->__lr-slide);
    for(int i=0;i<29;i++) fprintf(F,"x%d=%#llx\n",i,(ull)ss->__x[i]);
    fflush(F);
    // dump memory at every register that looks mapped (stack 0x16.., heap/binary 0x1..)
    for(int i=0;i<29;i++){ ull v=ss->__x[i]; char t[8]; snprintf(t,8,"x%d",i);
        if(v>0x100000000ULL && v<0x280000000ULL) { inhandler=1; tryread(t,v); }
        else if((v>>28)==0x16) { inhandler=1; tryread(t,v); } }
    inhandler=1; tryread("sp",ss->__sp);
    fclose(F); _exit(123);
}
__attribute__((constructor)) static void init(void){
    struct sigaction sa; memset(&sa,0,sizeof(sa)); sa.sa_sigaction=h; sa.sa_flags=SA_SIGINFO;
    sigaction(SIGSEGV,&sa,NULL); sigaction(SIGBUS,&sa,NULL);
    fprintf(stderr,"[observer] armed\n");
}
