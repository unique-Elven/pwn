#include <stdio.h>
void init(){
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    setbuf(stderr, 0);
}
void vuln(){
    char buf[8];
    puts(">>");
    read(0, buf, 0x100);
}
int main(){
    init();
    vuln();
    return 0;
}

// gcc ret2syscall.c -o ret2syscall -fno-stack-protector -no-pie -static

// gcc ret2syscall.c -o ret2syscall -fno-stack-protector -no-pie -static -m32
