#include <stdio.h>

void init(){
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    setbuf(stderr, 0);
}

void vuln(){
    char buf[0x100];
    for(int i = 0; i < 2; i++){
        puts(">>");
        read(0, buf, 0x100);
        printf(buf);
    }

}

int main(){
    init();
    vuln();
}
