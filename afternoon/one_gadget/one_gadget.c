#include <stdio.h>
#include <stdlib.h>

void init(){
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    setbuf(stderr, 0);
}

void vuln(){
    printf("gitf is 0x%lx\n", &puts);
    unsigned long long addr;
    puts("addr?");
    scanf("%lld", &addr);
    puts("value?");
    read(0, (void *)addr, 0x8);
    __asm(
    "xor rsi, rsi;"
    "xor rdx, rdx;"
    );
    exit(1);
}

int main(){
    init();
    vuln();
    return 0;
}

//gcc one_gadget.c -o one_gadget -fno-stack-protector -no-pie -masm=intel
