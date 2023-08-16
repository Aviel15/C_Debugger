# C_Debugger
Debugger in C language.

**It is a debugger for the Linux x86_64 system, that works while ASLR and PIE are enabled, the project was for educational purposes.**

**What is a debugger?**

A debugger is a software tool that helps programmers find and fix errors or bugs in their code. 
Debuggers allow programmers to step through their code line-by-line, inspect variables and memory contents, set breakpoints, and examine the program's state at specific points in its execution.

Debugging can be helpful in understanding how a program works, for exploring the behavior of unfamiliar code.



**Available Commands:**


**Breakpoint:** Set a breakpoint in the source line.


**Run:** Run until the breakpoint.


**Next source line:** Move to the next source line if not reached the last line.


**Print:** Prints the variable value or register values.


**Menu:** Show all the available commands and how to use them properly.


**Exit/Quit:** Exit from the program.



__How to develop a debugger in c language?__


**Using system calls:**

**Ptrace:** The  ptrace()  system call provides a means by which one process (the "tracer") may observe and control the execution of another process (the  "tracee") and  examine and  change  the  tracee's memory and registers.  
It is primarily used to implement breakpoint debugging and system call tracing.
(from mam command).

**Fork:** fork()  creates  a new process by duplicating the calling process. The new process is referred to as the child process. The calling process is referred to as the parent process. (from man command).

There are different options values returned by fork(). 
_Negative Value:_ The creation of a child process was unsuccessful.
_Zero:_ If we are in the child process, the fork returns 0
_Positive Value:_ if we are in the parent process, it returns the process ID of the child process.

**Exec:** The execl() is a system call that is responsible for loading and executing a new program in place of the currently running process.
 
**Wait:** Suspend the parent process execution until the child process state changes.




**How to set a breakpoint?**
 
**int 3 - 0xCC:** Software interrupt, INT 3 instruction generates a special one-byte opcode (0xCC) that is intended for calling the debug exception handler. replace the first byte of any instruction with a breakpoint.




**Where can I find appropriate information about debugging?**

Debug information generally refers to additional data that describes the program's original source code, data structures, variable declarations, and other details that are useful for debugging.

I used DWARF debugging information and with the libraries: #include <libdwarf/dwarf.h>, #include <libdwarf/libdwarf.h>.

_Pay attention:_
If your PIE is enabled, you will receive offset addresses and not fixed addresses, to get the fixed addresses you need to calculate -> offset address + base address of code segment = fixed address.

**libdwarf:** This is a C library that is used to consume and produce DWARF debug information.
To present the .debug_info section: objdump --dwarf=info binary_file
To present the .debug_line section: objdump --dwarf=decodedline binary_file



**How to execute the debugger program:**

1.   gcc debugger.c -o debugger -ldwarf  
2.   gcc -g <debugged_program>.c -o <debugged_program>
3.   ./debugger <debugged_program>

-ldwarf and -g are flags that supply the necessary information.
(To include DWARF debug information, the code needs to be compiled with the -g flag, which is not always the default setting).



**References:**


https://man7.org/linux/man-pages/man2/ptrace.2.html


https://eli.thegreenplace.net/2011/01/23/how-debuggers-work-part-1/ (All parts)


https://www.facebook.com/legacy/notes/1179415802105143/


https://blog.tartanllama.xyz/writing-a-linux-debugger-setup/ (All parts)


http://sigalrm.blogspot.com/2010/07/writing-minimal-debugger.html


https://wiki.osdev.org/DWARF


https://medium.com/@lizrice/a-debugger-from-scratch-part-1-7f55417bc85f


https://developer.ibm.com/articles/au-dwarf-debug-format/


https://nxmnpg.lemoda.net/3/dwarf (DWARF function documentation)


https://dwarfstd.org/doc/DWARF5.pdf (Helped to me with location expression mainly) 
