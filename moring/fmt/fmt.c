#include <stdio.h>

void init(){
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    setbuf(stderr, 0);
}

void vuln(){
    char buf[0x8];
    puts("name?");
    read(0, buf, 8);
    printf("Hello ");
    printf(buf);
    puts(">>");
    __asm(
        "xor rsi, rsi;"
        "xor rdx, rdx;"
    );
    read(0, buf, 0x20);
}

int main(){
    init();
    vuln();

}
