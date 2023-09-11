```sh
sudo apt-get install ruby -y
sudo apt-get install gem -y
sudo gem install one_gadget
sudo gem install seccomp-tools
```



### _IO_FILE 简单介绍

fd 文件句柄。在 ELF 程序当中

0 -> stdin -> 标准输入

1 -> stdout -> 标准输出

2 -> stderr -> 错误输出

在 程序 当中，如果要打开一个文件

close(2);

int flag_fd = open('flag', 0, 0);

flag_fd = 2



修改 stdout 的 filneo ，绕过 close

close(1);

puts("hello!");

修改 stdout -> filneo -> 2 ，那么又可以重新输入输出了



堆之后才用到

修改 _IO_2_1_stdout_ -> leak 内存信息

堆的高阶利用 ： 打 IO 结构体来劫持程序执行流
