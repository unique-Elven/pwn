#include <stdio.h>

char s[0x10] = ">>\n";

void init(){
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    setbuf(stderr, 0);
}
void game(){
    puts("Hello, hacker!");
    vuln();
}
void vuln(){
    __asm__(
    "sub rsp, 0x10;"
    "xor rax, rax;"
    "mov edx, 0x1000;"
    "lea rsi, [rsp + 8];"
    "xor rdi, rdi;"
    "syscall;"
    "mov edi, 1;"
    "lea rsi, [rsp + 8];"
    "mov edx, 0x30;"
    "push 1;"
    "pop rax;"
    "syscall;"
    "add rsp, 0x10;"
    );
}
int main(){
    init();
    game();
    return 0;
}

// gcc srop.c -o srop -fno-stack-protector -no-pie -masm=intel
