#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <string.h>

char name[0x10];

void init(){
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    setbuf(stderr, 0);
}

int vuln()
{
    char buf[0x20];
    puts(">>");
    gets(buf);
    return 0;
}
void backdoor(){
    system("/bin/sh");
}

int main()
{
    init();
    long long int num=555,love=520;
    long long int *pointer=&num;
    pthread_t newthread[5];

    puts("name?");
    read(0, name, 8);//由于在IDA查看发现第一个输入保存在了.bss段中所以什么用都没，没漏洞利用

    pthread_create(newthread,0,vuln,0);
    pthread_join(newthread[0], 0LL);
 
    return 0;
}

