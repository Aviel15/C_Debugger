#include "debugger.h"

//find the relative offset address of source line
int source_line(char* program_exec, int line_num){
    //initalize the dwarf debug information
    Dwarf_Debug dbg;
    int fd = open(program_exec, O_RDONLY);
    dwarf_init(fd, DW_DLC_READ, NULL, NULL, &dbg, NULL);   
    int ret = -1;

    Dwarf_Unsigned cu_header_length, abbrev_offset, next_cu_header;
    Dwarf_Half version_stamp, address_size;
    Dwarf_Line *linebuf;
    Dwarf_Signed linecount;
    //start at compilation unit - the first dwarf, move over the DIEs and checked which one is correct
    while (dwarf_next_cu_header(dbg_debug, &cu_header_length, &version_stamp, &abbrev_offset, &address_size, &next_cu_header, NULL) == DW_DLV_OK) {
        Dwarf_Die cu_die = 0;
        dwarf_siblingof(dbg_debug, NULL, &cu_die, NULL);

        //get the line address and line number of source line 
        dwarf_srclines(cu_die, &linebuf, &linecount, NULL);
        for (Dwarf_Signed i = 0; i < linecount; ++i) {
            Dwarf_Addr lineaddr;
            Dwarf_Unsigned lineno;
            //get the line address and line number
            dwarf_lineaddr(linebuf[i], &lineaddr, NULL);
            dwarf_lineno(linebuf[i], &lineno, NULL);
            //check if this line is the correct line, if yes, return his offset address
            if(lineno == line_num)
                return lineaddr;
            if(lineno > line_num)           //the search is in ascending order, so if the line number is bigger than source line input, the source line input exist but can't put there breakpoint
                ret = -2;                   //set brakpoint on exist line but like // of {}
        }
    }
    return ret;          //set breakpoint on not exist line number
}   

//find the memory address of source line and set brekpoint there
void breakpoint(DebuggerState* state, char* input, Breakpoint* breakpoint, int* flag_breakpoint_set){
    //check if already set breakpoint, each run of program can set one time breakpoint
    if(*flag_breakpoint_set){
        printf("You are already set a breakpoint.\n");
    }
    else {
        //find the space in the string and check if enter valid command, valid for instance - b 35
        char *space_ptr = strchr(input, ' ');                   
        if (space_ptr) 
            state->source_line_num = atoi(space_ptr+1);                            //convert the remaining string to int
        else {
            printf("Please enter valid command - b <source_line> or breakpoint <source_line>.\n");
            get_input(state);
        }
        char filename[FILE_LENGTH];
        FILE* maps_file;
        unsigned long start;
        
        //construct the maps filename for this process
        snprintf(filename, sizeof(filename), "/proc/%d/maps", state->child_pid);
        
        //open the maps file
        maps_file = fopen(filename, "r");
        if (maps_file == NULL) {
            perror("Error opening maps file");
            exit(1);
        }
        
        //read the base address of code segment
        fscanf(maps_file, "%lx-", &start);
        fclose(maps_file);

        //because the PIE and ASLR are enable, of DWARF get only the relative offset addresses, read them with source_line function
        unsigned long breakpoint_addr = source_line(state->program_exec, state->source_line_num);
        breakpoint->breakpoint_addr = breakpoint_addr; 
        //if the return value is -2, the set breakpoint was illegal       
        if(breakpoint_addr == -2)
            printf("Set breakpoint on legal line - not blank lines, not '{' or '}' lines : brackets, not '//' : double slash.\n");
        else if(breakpoint_addr == -1)                  //if the return value is -1, the source line number is not exist
            printf("This source line number is not exist.\n");
        else {
            //calculate the fix address, breakpoint_addr (offset address) + start (base address of code segment)
            breakpoint_addr = breakpoint_addr + start;
            //read the value from that address          
            long original_instr = ptrace(PTRACE_PEEKDATA, state->child_pid, (void*)breakpoint_addr, NULL);
            if(original_instr == -1)
                perror("ptrace");
            breakpoint->original_instr = original_instr;
            printf("Breakpoint at 0x%08lx: file %s.c, line %d.\n", breakpoint_addr, state->program_exec, state->source_line_num);

            //after found the memory address, set breakpoint with 0xCC
            long breakpoint_instr = (original_instr & ~0xFF) | 0xCC;
            ptrace(PTRACE_POKEDATA, state->child_pid, (void*)breakpoint_addr, (void*)breakpoint_instr);
            *flag_breakpoint_set = 1;
        }
    }
    get_input(state);
}

//check the data type of variable and print the value
void print_variable(pid_t child_pid, Dwarf_Die die, Dwarf_Debug dbg, long index_value, long index_addr){
    //get the value from DW_AT_type field
    Dwarf_Attribute type_attr;
    dwarf_attr(die, DW_AT_type, &type_attr, NULL);

    //the type is a offset reference to another DIE.
    Dwarf_Off type_die_offset;
    Dwarf_Error err;
    dwarf_global_formref(type_attr, &type_die_offset, &err);

    //DIE of array
    Dwarf_Die type_die;
    //finding the DIE via the offset that already found
    dwarf_offdie(dbg, type_die_offset, &type_die, NULL);
    Dwarf_Die array_die = type_die;         //save the array die

    int res = dwarf_attr(type_die, DW_AT_type, &type_attr, &err);
    int array = 0;          //if the variable is array it will equals to 1
    //if in the DIE exist again DW_AT_type field it means this is array
    if (res == DW_DLV_OK) {
        array = 1;
        dwarf_global_formref(type_attr, &type_die_offset, &err);
        dwarf_offdie(dbg, type_die_offset, &type_die, NULL);            //now type_die changed to the data type of array, for instance, char, int, long
    }

    //get the name of data type
    Dwarf_Attribute type_name_attr;
    dwarf_attr(type_die, DW_AT_name, &type_name_attr, NULL);

    //retrieves a string representation of a given attribute
    char* type_name;
    dwarf_formstring(type_name_attr, &type_name, &err);

    //if the data type is array
    if(array == 1){                                 
        Dwarf_Attribute upper_bound_attr;
        Dwarf_Unsigned upper_bound;

        Dwarf_Error error;
        Dwarf_Die child_die;

        //get the offset of DIE of data type, from DIEs like char, long, int, not arrays
        Dwarf_Off die_offset;
        int res = dwarf_dieoffset(array_die, &die_offset, &error);      

        //to all DW_TAG_array_type DIE has child that names DW_TAG_subrange_type and exist the size of the array
        res = dwarf_child(array_die, &child_die, &error);         
        if(res == DW_DLV_OK) {
            //get the size of array
            res = dwarf_attr(child_die, DW_AT_upper_bound, &upper_bound_attr, &err);
            if (res == DW_DLV_OK) {
                res = dwarf_formudata(upper_bound_attr, &upper_bound, &err);
                if (res == DW_DLV_OK) {
                    upper_bound = upper_bound + 1;
                }
            }
        }
        else if (res == DW_DLV_NO_ENTRY) {
            printf("No entry.\n");
        } else {                                            // res == DW_DLV_ERROR
            printf("Error.\n");
        }

        
        if(!strcmp(type_name, "int")) {
            for (int i = 0; i < upper_bound; ++i) {
                long value = ptrace(PTRACE_PEEKDATA, child_pid, index_addr + i * sizeof(int), NULL);         //read, cast to ont and print the array        
                int data = (int)value;
                printf("%d ", data);
            }
            printf("\n");
        }
        else if(!strcmp(type_name, "long int")) {
            for (int i = 0; i < upper_bound; ++i) {
                long value = ptrace(PTRACE_PEEKDATA, child_pid, index_addr + i * sizeof(long), NULL);         //read and print the array
                printf("%ld ", value);
            }
            printf("\n");            
        }
        else if(!strcmp(type_name, "char")) {
            for (int i = 0; i < upper_bound; ++i) {
                long value = ptrace(PTRACE_PEEKDATA, child_pid, index_addr + i * sizeof(char), NULL);          //read, cast to char and print the array       
                char data = (char)value;
                printf("%c", data);
            }
            printf("\n");
        }
        else if(!strcmp(type_name, "_Bool")) {
            for (int i = 0; i < upper_bound; ++i) {
                long value = ptrace(PTRACE_PEEKDATA, child_pid, index_addr + i * sizeof(bool), NULL);           //read, cast to boolean and print the array
                bool data = (bool)value;
                printf("%d ", data);
            }
            printf("\n");
        }
    }
    else {              //for non array variables
        if(!strcmp(type_name, "int")) {
            int data = (int)index_value;                //cast to int and print
            printf("%d\n", data);
        }
        else if(!strcmp(type_name, "long int"))         //print long
            printf("%ld\n", index_value);
        else if(!strcmp(type_name, "char")) {
            char data = (char)index_value;              //cast to char and print
            printf("%c\n", data);
        }
        else if(!strcmp(type_name, "_Bool")) {
            bool data = (bool)index_value;              //cast to boolean and print
            printf("%d\n", data);
        }
    }
}

//find the die of the printed variable
void find_die_of_var(pid_t child_pid, Dwarf_Debug dbg, Dwarf_Die die, char* name_compare, int* flag_found_var) {
    //retrieve the DW_AT_name attribute, if it exists
    Dwarf_Error err;
    Dwarf_Attribute attr_name;
    char* name;
    int res = dwarf_attr(die, DW_AT_name, &attr_name, &err);
    if (res == DW_DLV_OK) {                //check if die has DW_AT_name attribute, if has, will save the value in attr_name
        dwarf_formstring(attr_name, &name, &err);               //'name' contains the value of the DW_AT_name attribute
        if(!strcmp(name, name_compare)){                           //check if the name from die is same as expected variable name, if yes, found his DIE
            Dwarf_Attribute attr_loc;
            res = dwarf_attr(die, DW_AT_location, &attr_loc, &err);
            if (res == DW_DLV_OK) {                             //check if die has DW_AT_location
                Dwarf_Unsigned expr_len;
                Dwarf_Ptr block_ptr;
                if ((res = dwarf_formexprloc(attr_loc, &expr_len, &block_ptr, &err)) == DW_DLV_OK) {            //return information about a location expression.
                    unsigned char *data = (unsigned char *)block_ptr;
                    Dwarf_Small op = data[0];                           //for local variables, get the first byte, which is the operation code
                    if (op == DW_OP_fbreg) {
                        //the next bytes encode the offset from the frame base (RBP) as a signed LEB128 number.
                        Dwarf_Signed leb128_value;
                        Dwarf_Unsigned leb128_length;
                        char next_byte;
                        res = dwarf_decode_signed_leb128((char *)&data[1], &leb128_length, &leb128_value, &next_byte);
                        if (res == DW_DLV_OK) {
                            struct user_regs_struct regs;
                            ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
                            unsigned long long index_addr = regs.rbp + leb128_value + DIFFERENCE_SIZE;        //the difference between what i got from DIE to what actually got from gdb is +16
                            long index_value = ptrace(PTRACE_PEEKDATA, child_pid, (void*)index_addr, NULL);         //read value from variable's memory address

                            if (index_value == -1)
                                perror("ptrace");
                            else
                                print_variable(child_pid, die, dbg, index_value, index_addr);           //checked the variable data type and print the value
                        } 
                        else 
                           printf("Failed to decode leb128\n");
                    }
                    else if(op == DW_OP_addr)            //for global or static variables, which have a fixed address, unlike local variables which have an address that is determined relative to a stack or frame pointer at runtime.
                    {
                        //the next bytes encode the offset from the frame base (RBP) as a signed LEB128 number.
                        Dwarf_Signed leb128_value;
                        Dwarf_Unsigned leb128_length;
                        char next_byte;
                        res = dwarf_decode_leb128((char *)&data[1], &leb128_length, &leb128_value, &next_byte);
                        if (res == DW_DLV_OK) {
                            char filename[FILE_LENGTH];
                            FILE* maps_file;
                            unsigned long start;
                            
                            //construct the maps filename for this process
                            snprintf(filename, sizeof(filename), "/proc/%d/maps", child_pid);
                            
                            //open the maps file
                            maps_file = fopen(filename, "r");
                            if (maps_file == NULL) {
                                perror("Error opening maps file");
                                exit(1);
                            }
                            
                            //read the start address of the first mapping - base address of code segment, because to global variables have not stack, so got offset addresses
                            fscanf(maps_file, "%lx-", &start);
                            fclose(maps_file);

                            //skip the first byte (DW_OP_addr), start from the second byte
                            uint64_t addr = 0;
                            for (size_t i = 0; i < 4; i++) {                                        //loop through 4 bytes
                                addr |= ((uint64_t)data[i + 1]) << (i * 8);
                            }
                            addr = addr + start;                //add the base addresss to the offset
                            long index_value = ptrace(PTRACE_PEEKDATA, child_pid, (void*)addr, NULL);           //read the data from global variable's memory address

                            print_variable(child_pid, die, dbg, index_value, addr);            //print the variable's value
                        }
                    } 
                    else 
                        printf("Unexpected operation: %d\n", op);
                    //deallocate the location expression
                    dwarf_dealloc(dbg, block_ptr, DW_DLA_LOC_BLOCK);
                }
                else {
                    if (res == DW_DLV_ERROR) {
                        printf("Error getting loclist: %s\n", dwarf_errmsg(err));
                    } else if (res == DW_DLV_NO_ENTRY) {
                        printf("No loclist for this attribute.\n");
                    }
                }
                *flag_found_var = 1;          //set to know if the found process worked well
            }
        }

        //deallocate the attribute after using it
        dwarf_dealloc(dbg, attr_name, DW_DLA_ATTR);
    }

    //process all child DIEs
    Dwarf_Die child;
    if (dwarf_child(die, &child, &err) == DW_DLV_OK) {
        do {
            find_die_of_var(child_pid, dbg, child, name_compare, flag_found_var);            //recursion
        } while (dwarf_siblingof(dbg, child, &child, &err) == DW_DLV_OK);
    }
}

/**
 * get registers values
*/
void print_registers(int child_pid){
        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);     //get registers

        printf("RAX: 0x%llx\n", regs.rax);
        printf("RBX: 0x%llx\n", regs.rbx);
        printf("RCX: 0x%llx\n", regs.rcx);
        printf("RDX: 0x%llx\n", regs.rdx);
        printf("RSI: 0x%llx\n", regs.rsi);
        printf("RDI: 0x%llx\n", regs.rdi);
        printf("RIP: 0x%llx\n", regs.rip);
        printf("RBP: 0x%llx\n", regs.rbp);
        printf("RSP: 0x%llx\n", regs.rsp);
        printf("R8:  0x%llx\n", regs.r8);
        printf("R9:  0x%llx\n", regs.r9);
        printf("R10: 0x%llx\n", regs.r10);
        printf("R11: 0x%llx\n", regs.r11);
        printf("R12: 0x%llx\n", regs.r12);
        printf("R13: 0x%llx\n", regs.r13);
        printf("R14: 0x%llx\n", regs.r14);
        printf("R15: 0x%llx\n", regs.r15);
}

//call to methods to print the variable or registers and reset the DWARF information
void print(DebuggerState* state, char* input){
    Dwarf_Error err;
    input[strcspn(input, "\n")] = 0;         //remove the newline character from a string, strcspn find the first appreance on new line in input   

    char *substring = strchr(input, ' ');
    char *name;
    if (substring) 
        name = substring + 1;                   //skip the space character
    else {
        printf("Please enter valid command with valid variable name - p <variable_name> or print <variable_name>.\n");
        get_input(state);
    }

    if(!strcmp(name, "registers")){            //print registers
        print_registers(state->child_pid);
    }
    else{
        //reset the DWARF information to point the start
        dwarf_finish(dbg_debug, &err);
        int fd = open(state->program_exec, O_RDONLY);
        if (dwarf_init(fd, DW_DLC_READ, 0, 0, &dbg_debug, &err) != DW_DLV_OK) {          //because the print command use after run command, the DWARF information not point to the start and need fix that
            fprintf(stderr, "Failed DWARF initialization\n");
            exit(1);
        }

        Dwarf_Die cu_die;

        //iterate over all Compilation Unit (CU) headers
        if (dwarf_next_cu_header(dbg_debug, NULL, NULL, NULL, NULL, NULL, &err) == DW_DLV_OK) {
            //get the root DIE of the CU
            dwarf_siblingof(dbg_debug, NULL, &cu_die, &err);
            //process this DIE and its children
            int flag_found_var = 0;             //pointer to check if found the variable well
            find_die_of_var(state->child_pid, dbg_debug, cu_die, name, &flag_found_var);
            if (!flag_found_var) {
                printf("Please enter valid command with valid variable name - p <variable_name> or print <variable_name>.\n");
            }
        }
    }
    get_input(state);
}

//initialize the relevant arrays to next command
void initialize_next(ArraysData* arraysData){
    //for offset addresses
    int num_addresses = 0;

    const char* command = "objdump --dwarf=decodedline check";      //the command that gives a map between source lines to thier relative offset

    FILE* fp = popen(command, "r");

    if (fp == NULL) {
        printf("Could not open file\n");
        exit(1);
    }

    char buffer[FILE_LENGTH];
    //check that not occurs any errors and not reached to end of file
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        unsigned long long address_offset;      //hold the offset address
        char line_num[MAX_LINE_LEN];           //hold the line number

        //read formatted input from a string, stored in buffer, the matches variable will contain the number of successful assignments
        int matches = sscanf(buffer, "check.c %s 0x%llx %*s %*c", line_num, &address_offset);      
        //process both line number and address in the same loop
        if (matches == 2 && num_addresses < MAX_ADDRESSES && strcmp(line_num, "-") != 0) {          //two matches is the right case, line number and address
            arraysData->line_numbers[num_addresses] = atoi(line_num);
            arraysData->address_array[num_addresses] = address_offset;
            num_addresses++;
        }
    }

    pclose(fp);
}

//find the memory address of next source line and set there breakpoint 
void find_next(DebuggerState* state, char* input, int source_line_num){
    
    if(strchr(input, ' ')) {                    //check if enter valid command
        printf("Please enter valid command - next or n only\n");
        get_input(state);
    }
    static int init_next = 0;
    static ArraysData arraysData;           //struct for array of addresses and array of line numbers
    if(!init_next) {                        //initialize the next information, because need make once check if already did.
        initialize_next(&arraysData);
        init_next = 1;          //set to 1 because need to initialize only once the map between source line and offsets
    }


    int index = 0;
    int n = sizeof(arraysData.line_numbers) / sizeof(arraysData.line_numbers[0]);         //calculate the line numbers of program
    int last_index = n - 1;
    while(arraysData.line_numbers[index] <= source_line_num && index != last_index)       //increasing until reach the right source line
        index++;

    if(index == last_index){                                                    //announces that have reached the last source line
        printf("You have reached the last line of your code.\n");
        get_input(state);
    }

    state->source_line_num++;                              //in the next command will execute until this next new line
    char filename[FILE_LENGTH];
    FILE* maps_file;
    unsigned long start;
        
    //construct the maps filename for this process
    snprintf(filename, sizeof(filename), "/proc/%d/maps", state->child_pid);
    
    //open the maps file
    maps_file = fopen(filename, "r");
    if (maps_file == NULL) {
        perror("Error opening maps file");
        exit(1);
    }
        
    //read the start address of the first mapping
    fscanf(maps_file, "%lx-", &start);
    fclose(maps_file);

    //calculate the breakpoint address - offset + base address of code segment (start)
    unsigned long break_address = arraysData.address_array[index] + start;
    Breakpoint breakpoint;
    breakpoint.breakpoint_addr = break_address;

    //store the orginial instruction to save him after the implemention of next command
    long original_instr = ptrace(PTRACE_PEEKDATA, state->child_pid, (void*)break_address, NULL);
        if(original_instr == -1)
            perror("ptrace");
    breakpoint.original_instr = original_instr;

    //to reach the next source line need to set a breakpoint at his address, and then when run the program he will stop at next source line        
    long breakpoint_instr = (original_instr & ~0xFF) | 0xCC;
    ptrace(PTRACE_POKEDATA, state->child_pid, (void*)break_address, (void*)breakpoint_instr);

    //run to break point after set one
    run_to_break(state, arraysData.line_numbers[index], &breakpoint, NULL);             
    get_input(state);
} 

//running until the breakpoint address, gets the source line, breakpoint address and instruction of breakpoint address
void run_to_break(DebuggerState* state, int source_line_num, Breakpoint* breakpoint, int* flag_run_set){
    //resume execution
    ptrace(PTRACE_CONT, state->child_pid, NULL, NULL);

    //wait for the child process to stop again
    waitpid(state->child_pid, &state->wait_status, 0);

    if (WIFSTOPPED(state->wait_status)) {              //return true if the child process was stopped by delivery of a signal, signal from child process - SIGSTOP.
        ptrace(PTRACE_GETREGS, state->child_pid, 0, &state->regs);
        printf("Run until line %d in %s.c.\n", source_line_num, state->program_exec);
        //restore the original instruction at the breakpoint
        ptrace(PTRACE_POKETEXT, state->child_pid, (void*)breakpoint->breakpoint_addr, (void*)breakpoint->original_instr);
    }
    else 
        perror("wait");                         //error - not stopped by another process
    //get child's registers and adjust rip back to the original instruction
    ptrace(PTRACE_GETREGS, state->child_pid, NULL, &state->regs);
    state->regs.rip = breakpoint->breakpoint_addr;
    ptrace(PTRACE_SETREGS, state->child_pid, NULL, &state->regs);

    //this variable matter only for run command, because I can use next command how much I want during that run command only once
    if(flag_run_set != NULL)          
        *flag_run_set = 1;            //now can't run the program again
}

//check if can be run the program, run only if there is breakpoint.
void run(DebuggerState* state ,char* input, Breakpoint breakpoint, int flag_breakpoint_set) {
    if(strchr(input, ' ')) {                    //check if enter valid command
        printf("Please enter valid command - run or r only.\n");
        get_input(state);
    }
    static int flag_run_set = 0;
    if(flag_run_set == 1) {                           //check if already ran the program
        printf("You are already running the program.\n");
        get_input(state);
    }
    if(flag_breakpoint_set == 0)                         
        printf("Please set a new breakpoint before running the program.\n");
    else 
        run_to_break(state, state->source_line_num, &breakpoint, &flag_run_set);             //call to run method that actually run with memory using
    get_input(state);
}

/**
 * this function wait for input from user - a method that call to relevant command
*/
void get_input(DebuggerState* state){
    char input[MAX_ADDRESSES];
    char command[MAX_ADDRESSES];
    printf("(dbg) ");
    fgets(input, sizeof(input), stdin);     //get from stdin to input variable
    strncpy(command, input, MAX_ADDRESSES);                 //make a copy of input
    strtok(command, " \n");                 //breaks the string into tokens " "
    int len = strlen(command);
    static int flag_breakpoint_set = 0;

    Breakpoint bpoint;

    if((input[0] == 'b' && strlen(command) == 1) || !strcmp(command, "break")) {            //set a breakpoint
        breakpoint(state, input, &bpoint, &flag_breakpoint_set);
    }
    else if((input[0] == 'r' && strlen(command) == 1) || !strcmp(command, "run")) {         //run the program
        run(state, input, bpoint, flag_breakpoint_set);
    }
    else if((input[0] == 'n' && strlen(command) == 1) || !strcmp(command, "next")) {        //move next line in source code (not next instruction)
        find_next(state, input, state->source_line_num);
    }
    else if((input[0] == 'p' && strlen(command) == 1) || !strcmp(command, "print")) {       //print the value of variable/registers
        print(state, input);
    }
    else if(!strcmp(command, "exit") || !strcmp(command, "quit")) {
        //detach from the child process
        ptrace(PTRACE_DETACH, state->child_pid, NULL, NULL);
        exit(0);
    }
    else if(!strcmp(command, "menu")) {
        printf("b/break <line_number> - set breakpoint in specific line number\n");
        printf("r/run - run the program\n");
        printf("n/next - single step forward\n");
        printf("p/print <variable_name> - print the value in the variable\n");
        printf("exit/quit - exit from debugging program\n");
        get_input(state);
    }
    else {
        printf("Unknown comamnd\n");
        get_input(state);
    }
}

//initialize the dwarf file information
void init(char* argv, DebuggerState* state) {
    Dwarf_Error err;
    int fd = -1;
    
    state->child_pid = fork();             //create child process
    state->program_exec = argv;

    if ((fd = open(argv, O_RDONLY)) < 0) {      //open the file
        perror("open");
        exit(1);
    }

    if (dwarf_init(fd, DW_DLC_READ, 0, 0, &dbg_debug, &err) != DW_DLV_OK) {      //init the dwarf information
        fprintf(stderr, "Failed DWARF initialization\n");
        exit(1);
    }
}

int main(int argc, char *argv[]) {   
    if(argc != 2){
        printf("Usage: ./debugger <program_to_debug>\n");
        exit(1);                                //exit with error
    }
    DebuggerState state;

    init(argv[1], &state);
    
    if (state.child_pid == -1) {
        perror("fork");
        exit(EXIT_FAILURE);
    } 
    else if(state.child_pid == 0) {
        //this block will be executed by the child process
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);      //trace to parent process
        execl(argv[1], argv[1], NULL);              //replaces the current process image with a new image process that is the program to debug
        perror("exec");
        exit(1);
    }
    else {
        //this block will be executed by the parent process
        get_input(&state);
    }
    return 0;
}
