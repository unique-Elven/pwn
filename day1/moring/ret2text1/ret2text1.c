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
void backdoor(){
    system("/bin/sh");
}
int main(){
    init();
    vuln();
    return 0;
}

// gcc ret2text1.c -o ret2text1 -fno-stack-protector -no-pie

// gcc ret2text1.c -o ret2text1 -fno-stack-protector -no-pie -m32
