#include <stdio.h>

void init(){
	setbuf(stdin, 0);
	setbuf(stdout, 0);
	setbuf(stderr, 0);
}

int main(){
	init();
	close(1);
	system("/bin/sh");
}
