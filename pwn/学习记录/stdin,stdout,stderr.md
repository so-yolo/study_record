在pwn题目中，`stderr`、`stdin`、`stdout`分别对应标准错误输出流、标准输入流和标准输出流。它们在C语言库中通常以全局变量的形式存在，具体位置如下：

1. `stdin`：标准输入流，通常对应于文件描述符0。在glibc中，`stdin`是一个`_IO_FILE`结构体的实例，可以通过`_IO_2_1_stdin_`访问。
    
2. `stdout`：标准输出流，通常对应于文件描述符1。在glibc中，`stdout`也是一个`_IO_FILE`结构体的实例，可以通过`_IO_2_1_stdout_`访问。
    
3. `stderr`：标准错误输出流，通常对应于文件描述符2。在glibc中，`stderr`也是一个`_IO_FILE`结构体的实例，可以通过`_IO_2_1_stderr_`访问

![[Pasted image 20241201212613.png]]

`stderr`用于输出错误信息，而`stdout`用于输出程序的正常输出