#include <stdio.h>

void init(){
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    setbuf(stderr, 0);
}
void vuln1(){
    vuln2();
}
void vuln2(){
    char buf[8];
    puts(">>");
    read(0, buf, 0x100);
}
void backdoor(){
    system("/bin/sh");
}
int main(){
    init();
    vuln1();
    return 0;
}

// gcc pie.c -o pie -fno-stack-protector
