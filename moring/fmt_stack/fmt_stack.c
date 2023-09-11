#include <stdio.h>

void init(){
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    setbuf(stderr, 0);
}
void vuln(){
    char buf[0x100];
    while(1){
        puts(">>");
        read(0, buf, 0x100);
        printf(buf);
    }
}
int main(){
    init();
    vuln();
}
