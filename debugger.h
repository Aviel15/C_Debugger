#ifndef DEBUGGER_H
#define DEBUGGER_H

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/reg.h>   
#include <sys/user.h>  
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libdwarf/dwarf.h>
#include <libdwarf/libdwarf.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdbool.h>

#define MAX_ADDRESSES 100
#define FILE_LENGTH 256
#define MAX_LINE_LEN 10
#define DIFFERENCE_SIZE 16      //the difference between what I got from DIE information to what actually got from gdb in runtime is +16

/* debugger state */
typedef struct {
    int wait_status;
    pid_t child_pid;
    char* program_exec;
    struct user_regs_struct regs;
    int source_line_num;
} DebuggerState;

/* breakpoint information about memory addresses */
typedef struct {
    unsigned long breakpoint_addr;
    long original_instr;   
} Breakpoint;

/* arrays data mapping between memory address to source lines */
typedef struct {
    unsigned long long address_array[MAX_ADDRESSES];
    int line_numbers[MAX_ADDRESSES];
} ArraysData;

Dwarf_Debug dbg_debug = 0;

/* Prototypes */

/**
 * @brief return the offset address of specific source line from the program.
 * @param program_exec the program is debugged.
 * @param line_num the source line.
 * @return offset address of source line.
*/
int source_line(char* program_exec, int line_num);

/**
 * @brief find the memory address of breakpoint source line and set there breakpoint.
 * @param state state struct information about debugger.
 * @param input the input that user insert, to know which source line set a breakpoint.
 * @param breakpoint breakpoint struct information.
 * @param flag_breakpoint_set set to 1 if set the breakpoint was successful, else set to 0.
*/
void breakpoint(DebuggerState* state, char* input, Breakpoint* breakpoint, int* flag_breakpoint_set);

/**
 * @brief check the data type of variable and print the value.
 * @param child_pid child process id, of program debugged.
 * @param die die's variable.
 * @param dbg debug information of variable.
 * @param index_value the value of variables, using for local variables.
 * @param index_addr the memory address of variables, using of global/static variables (which on heap and not stack).
*/
void print_variable(pid_t child_pid, Dwarf_Die die, Dwarf_Debug dbg, long index_value, long index_addr);

/**
 * @brief find the die of the printed variable.
 * @param child_pid child process id, of program debugged.the program is debugged.
 * @param dbg the source line.debug information of variable.
 * @param die die's variable.
 * @param name the name of variable to print.
 * @param flag_found_var set to 1 if found variable was successful, else set to 0.
*/
void find_die_of_var(pid_t child_pid, Dwarf_Debug dbg, Dwarf_Die die, char* name, int* flag_found_var);

/**
 * @brief get registers values.
 * @param child_pid child process id, of program debugged.the program is debugged.
*/
void print_registers(int child_pid);

/**
 * @brief wait for input from user, and than call to relevant command.
 * @param state state struct information about debugger.
*/
void get_input(DebuggerState* state);

/**
 * @brief call to methods to print the variable or registers and reset the DWARF information.
 * @param state state struct information about debugger.
 * @param input the input that user insert, to know what source variable's name.
*/
void print(DebuggerState* state, char* input);

/**
 * @brief initialize the relevant arrays (address array and source line array) to next command.
*/
void initialize_next();

/**
 * @brief find the memory address of next source line and set there breakpoint.
 * @param state state struct information about debugger.
 * @param input the input that user insert, to check if the command entered well.
 * @param source_line_num the source line.
*/
void find_next(DebuggerState* state, char* input, int source_line_num);

/**
 * @brief running until the breakpoint address.
 * @param state state struct information about debugger.
 * @param source_line_num the source line.
 * @param breakpoint breakpoint struct information.
 * @param flag_run_set set to 1 if the run was successful, else set to 0.
*/
void run_to_break(DebuggerState* state, int source_line_num, Breakpoint* breakpoint, int* flag_run_set);

/**
 * @brief check if can be run the program, run only if there is breakpoint.
 * @param state state struct information about debugger.
 * @param input the input that user insert, to check if the command entered well.
 * @param breakpoint breakpoint struct information.
 * @param flag_breakpoint_set set to 1 if set the breakpoint was successful, else set to 0.
*/
void run(DebuggerState* state, char* input, Breakpoint breakpoint, int flag_breakpoint_set);

/** 
 * @brief initialize the dwarf file information.
 * @param argv argv[1], the program name that the user entered via terminal to debug.
 * @param state state struct information about debugger.
*/
void init(char* argv, DebuggerState* state);

#endif  /* DEBUGGER_H */
