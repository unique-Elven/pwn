#include <stdio.h>

void init(){
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    setbuf(stderr, 0);
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

// gcc ret2shellcode.c -o ret2shellcode -fno-stack-protector -no-pie -z execstack

//canary：-fno-stack-protector
//pie：-no-pie
//NX：-z execstack