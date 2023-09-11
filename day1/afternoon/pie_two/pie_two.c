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
    printf("is %s\n", (char *)buf);
}
int main(){
    init();
    puts("Hello, Hacker!");
    vuln();
    return 0;
}

// gcc pie_two.c -o pie_two -fno-stack-protector 
