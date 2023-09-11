#include <stdio.h>

char buf[0x100];

void init(){
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    setbuf(stderr, 0);
}

void vuln(){
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
