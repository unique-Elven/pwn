#include <stdio.h>

char name[0x100];
void init(){
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    setbuf(stderr, 0);
}
void vuln(){
    char buf[0x8];
    system("echo name?");
    read(0, name, 0x1000);
    printf("Hello, %s\n", name);
    puts(">>");
    read(0, buf, 0x18);
}
void backdoor(){
    system("echo flag");
}
int main(){
    init();
    vuln();
}

// gcc Stack_migration.c -o  Stack_migration -fno-stack-protector -no-pie
