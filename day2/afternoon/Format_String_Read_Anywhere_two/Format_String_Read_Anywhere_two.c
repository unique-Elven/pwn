#include <stdio.h>

void init(){
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    setbuf(stderr, 0);
}
void vuln(){
    char flag[0x30], buf[0x30];
    int fd = open("flag", 0, 0);
    read(fd, flag, 0x30);
    puts(">>");
    read(0, buf, 0x30);
    printf(buf);
}
int main(){
    vuln();
    return 0;
}

// gcc Format_String_Read_Anywhere_two.c -o Format_String_Read_Anywhere_two
