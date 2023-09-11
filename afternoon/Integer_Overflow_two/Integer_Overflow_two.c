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
    char * ptr = alloca(8 * num);
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

