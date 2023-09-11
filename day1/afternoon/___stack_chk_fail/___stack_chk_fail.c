#include <stdio.h>

void init(){
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    setbuf(stderr, 0);
}
void magic(){
    unsigned long long addr;
    puts("addr?");
    scanf("%lld", &addr);//写入got表的地址
    puts("value?");
    read(0, (void *)addr, 0x8);
}
void vuln(){
    char buf[8];
    puts(">>");
    read(0, buf, 0x100);
}
int main(){
    init();
    magic();
    vuln();
    return 0;
}

// gcc ___stack_chk_fail.c -o ___stack_chk_fail -no-pie
