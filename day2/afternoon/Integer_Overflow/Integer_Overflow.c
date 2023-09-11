#include <stdio.h>
#include <stdlib.h>

void init(){
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    setbuf(stderr, 0);
}
void vuln(){
    char buf[8];
    unsigned int size; // size = -1 = 0xffffffff
    puts("size?");
    scanf("%d", &size);
    if((int)size > 8){ // size = -1 < 8
        puts("error");
        exit(1);
    }
    puts(">>");
    read(0, buf, size); // size = 0xffffffff
}
int main(){
    init();
    vuln();
    return 0;
}

// gcc Integer_Overflow.c -o Integer_Overflow -fno-stack-protector -no-pie

