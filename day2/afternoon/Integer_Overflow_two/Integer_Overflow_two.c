#include <stdio.h>
#include <stdlib.h>
int num;

void init(){
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    setbuf(stderr, 0);
}
void vuln(){
    puts("size?");
    scanf("%d", &num);
    char * ptr = alloca(8 * num); // alloca 函数是用来在栈上开辟空间的，其汇编指令形式是 sub rsp, 0xk;
    for(int i = 0; i < 10; i++){
        int idx;
        puts("idx?");
        scanf("%d", &idx);
        if(idx <= num){
            puts("value?");
            read(0, (char *)(ptr + idx * 8), 8);
        }else{
            puts("no!");
        }
    }
    
}
int main(){
    init();
    vuln();
    return 0;
}

// gcc Integer_Overflow_two.c -o Integer_Overflow_two -no-pie

// 如果 num = 0x20000010 其 *8 = 0x100000080 ，那么 alloca(8 * num) = alloca(0x100000080) = alloc(0x80) - sub rsp, 0x90
// 这个时候 idx 就可以很大，直接修改返回地址的值
