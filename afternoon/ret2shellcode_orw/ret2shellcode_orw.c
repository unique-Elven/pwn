#include <stdio.h>
#include<unistd.h>
#include <seccomp.h>
 
void sandbox()
{
    scmp_filter_ctx ctx;
    ctx =seccomp_init(SCMP_ACT_ALLOW);
    seccomp_rule_add(ctx,SCMP_ACT_KILL,SCMP_SYS(execve),0);
    seccomp_load(ctx);
}
void init(){
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    setbuf(stderr, 0);
    sandbox();
}
void vuln(){
    char buf[8];
    printf("gift : 0x%lx\n", &buf); 
    puts(">>");
    read(0, buf, 0x100);
}
int main(){
    init();
    vuln();
    return 0;
}

// gcc ret2shellcode_orw.c -o ret2shellcode_orw -fno-stack-protector -no-pie -z execstack -lseccomp
