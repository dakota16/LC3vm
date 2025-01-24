#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <windows.h>
#include <conio.h>

// & is the bitwise AND operator. It takes two numbers as operands and does AND on every bit of two numbers. The result of AND is 1 only if both bits are 1. This can thus be used to isolate a specific bit in a number. This is called masking.

enum { //Registers - 8 general purpose registers, a program counter, and a condition code register.
    R_R0 = 0,
    R_R1,
    R_R2,
    R_R3,
    R_R4,
    R_R5,
    R_R6, 
    R_R7, 
    R_PC, //Program Counter
    R_COND, //Condition flags
    R_COUNT //Number of registers
};

enum { //Flags - 3 condition flags that can be set based on the result of an operation. Only the last 3 bits of the condition register are used.
    FL_POS = 1 << 0, // 001 in binary
    FL_ZRO = 1 << 1, // 010 in binary
    FL_NEG = 1 << 2 // 100 in binary
};

enum { //F*CK ENUMS, the amount of time it took me to figure out that enums had to be in a specific order to work properly was ridiculous.
    OP_BR = 0, // Branch
    OP_ADD,    // ADD
    OP_LD,     // Load
    OP_ST,     // Store
    OP_JSR,    // Jump register
    OP_AND,    // Bitwise AND
    OP_LDR,    // Load register
    OP_STR,    // Store register
    OP_RTI,    // Unused
    OP_NOT,    // Bitwise NOT
    OP_LDI,    // Load indirect
    OP_STI,    // Store indirect
    OP_JMP,    // Jump
    OP_RES,    // Reserved (unused)
    OP_LEA,    // Load effective address
    OP_TRAP    // Execute trap
};

enum {
    MR_KBSR = 0xFE00, // Keyboard status register
    MR_KBDR = 0xFE02 // Keyboard data register
};

enum { //System calls that allow a program to interact with the operating system.
    TRAP_GETC = 0x20, // get character from keyboard, not echoed onto the terminal
    TRAP_OUT = 0x21, // output a character
    TRAP_PUTS = 0x22, // output a word string
    TRAP_IN = 0x23, // get character from keyboard, echoed onto the terminal
    TRAP_PUTSP = 0x24, // output a byte string
    TRAP_HALT = 0x25 // halt the program
};

#define MEMORY_MAX (1 << 16) // 2^16 = 65536
uint16_t memory[MEMORY_MAX]; //Memory
uint16_t reg[R_COUNT]; //Registers

HANDLE hStdin = INVALID_HANDLE_VALUE;
DWORD fdwMode, fdwOldMode;

void disable_input_buffering()
{
    hStdin = GetStdHandle(STD_INPUT_HANDLE);
    GetConsoleMode(hStdin, &fdwOldMode); /* save old mode */
    fdwMode = fdwOldMode & ~(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT);
    SetConsoleMode(hStdin, fdwMode); /* set new mode */
    FlushConsoleInputBuffer(hStdin); /* clear buffer */
}

void restore_input_buffering() // Restore input buffering
{
    SetConsoleMode(hStdin, fdwOldMode);
}

uint16_t check_key() // Check if a key has been pressed
{
    return WaitForSingleObject(hStdin, 1000) == WAIT_OBJECT_0 && _kbhit();
}

void handle_interrupt(int signal) // Handle interrupts
{
    restore_input_buffering();
    printf("\n");
    exit(-2);
}

uint16_t sign_extend(uint16_t *x, int bit_count)
{
    const uint16_t sign_bit_mask = 1 << (bit_count - 1);
    const uint16_t extension_mask = 0xFFFF << bit_count;

    if (*x & sign_bit_mask) 
    {
        *x |= extension_mask;
    }

    return *x;
}

uint16_t swap16(uint16_t x) // Swap the endianness of a 16-bit number.
{
    return (x << 8) | (x >> 8);
}

void update_flags(uint16_t r) // Update the condition flags based on the value in a register.
{
    if (reg[r] == 0) 
    {
        reg[R_COND] = FL_ZRO;
    } 
    else if (reg[r] >> 15) // a 1 in the leftmost bit indicates a negative number
    {
        reg[R_COND] = FL_NEG;
    } 
    else 
    {
        reg[R_COND] = FL_POS;
    }
}

void read_image_file(FILE* file) // Read the image file.
{
    uint16_t origin;
    fread(&origin, sizeof(origin), 1, file);
    origin = swap16(origin);

    uint16_t max_read = MEMORY_MAX - origin;
    uint16_t* p = memory + origin;
    size_t read = fread(p, sizeof(uint16_t), max_read, file);

    while (read-- > 0)
    {
        *p = swap16(*p);
        ++p;
    }
}

int read_image(const char* image_path)
{
    FILE* file = fopen(image_path, "rb");
    if (!file) { return 0; };
    read_image_file(file);
    fclose(file);
    return 1;
}

void mem_write(uint16_t address, uint16_t val) // Write to memory at a given address.
{
    memory[address] = val;
}

uint16_t mem_read(uint16_t address) // Read from memory at a given address.
{
    if (address == MR_KBSR) // Keyboard status register
    {
        if (check_key()) // If a key has been pressed
        {
            memory[MR_KBSR] = (1 << 15); // Set the leftmost bit of the keyboard status register to 1
            memory[MR_KBDR] = getchar(); // Get the character from the keyboard and store it in the keyboard data register
        }
        else
        {
            memory[MR_KBSR] = 0; // Set the keyboard status register to 0
        }
    }
    return memory[address];
}

int main(int argc, const char* argv[]) 
{
    printf("Starting LC-3 VM...\n");
    if (argc < 2)
    {
        printf("lc3 [image-file1] ...\n");
        exit(2);
    }

    for (int j = 1; j < argc; ++j)
    {
        if (!read_image(argv[j]))
        {
            printf("failed to load image: %s\n", argv[j]);
            exit(1);
        }
    }
    signal(SIGINT, handle_interrupt);
    disable_input_buffering();

    reg[R_COND] = FL_ZRO; 
    enum { PC_START = 0x3000 }; // The program counter starts at 0x3000. Everything before that is reserved for the operating system.
    reg[R_PC] = PC_START; // The program counter is set to the starting address.

    int running = 1;
    while (running)
    {
        uint16_t instr = mem_read(reg[R_PC]++);
        uint16_t op = instr >> 12; 

        switch (op) // Decode the opcode and perform the operation.
        {
            case OP_ADD:
                {
                    uint16_t r0 = (instr >> 9) & 0x7;// The destination register is the 3 bits after the opcode. Shift by 9 to get the 3 bits after the opcode.
                    uint16_t r1 = (instr >> 6) & 0x7;// The first operand register is the 3 bits after the destination register. Shift by 6 to get the 3 bits after the destination register.
                    uint16_t imm_flag = (instr >> 5) & 0x1;// The immediate flag is the bit after the first operand register. Shift by 5 to get the bit after the first operand register.
                    
                    if (imm_flag) // If the immediate flag is set, add the immediate value to the first operand register.
                    {
                        uint16_t imm5 = instr & 0x1F; // The immediate value is the 5 bits after the immediate flag. Mask with 0x1F is 11111 in binary so will mask the 5 bits after the immediate flag.
                        sign_extend(&imm5, 5); // Sign extend the immediate value to 16 bits.
                        reg[r0] = reg[r1] + imm5;
                    }
                    else
                    {
                        uint16_t r2 = instr & 0x7; // The second operand register is the 3 bits after the first operand register. Mask with 0x7 to get the 3 bits.
                        reg[r0] = reg[r1] + reg[r2];
                    }
                    update_flags(r0);
                }
                break;
                
            case OP_AND: // Same as OP_ADD, but with bitwise AND instead of addition.
                {
                    uint16_t r0 = (instr >> 9) & 0x7; // 0x7 is 111 in binary. So this masks the 3 bits after the opcode to get the destination register.
                    uint16_t r1 = (instr >> 6) & 0x7; 
                    uint16_t imm_flag = (instr >> 5) & 0x1;
                    
                    if (imm_flag)
                    {
                        uint16_t imm5 = instr & 0x1F;
                        sign_extend(&imm5, 5);
                        reg[r0] = reg[r1] & imm5;
                    }
                    else
                    {
                        uint16_t r2 = instr & 0x7;
                        reg[r0] = reg[r1] & reg[r2];
                    }
                    update_flags(r0);
                }
                break;

            case OP_NOT:
                {
                    uint16_t r0 = (instr >> 9) & 0x7;
                    uint16_t r1 = (instr >> 6) & 0x7;
                    reg[r0] = ~reg[r1]; // Bitwise NOT
                    update_flags(r0);
                }
                break;

            case OP_BR:
                {
                    uint16_t pc_offset = instr & 0x1FF; // The PC offset is the 9 bits after the opcode. Mask with 0x1FF to get the 9 bits.
                    sign_extend(&pc_offset, 9);
                    uint16_t cond_flag = (instr >> 9) & 0x7; 
                    if (cond_flag & reg[R_COND]) // If the condition flag is set
                    {
                        reg[R_PC] += pc_offset; // Branch
                    }
                }
                break;

            case OP_JMP:
                {
                    uint16_t r1 = (instr >> 6) & 0x7; // The base register is the 3 bits after the opcode. Shift by 6 to get the 3 bits then mask first 3 bits.
                    reg[R_PC] = reg[r1]; // Jump to the address in the register
                }
                break;

            case OP_JSR:
                {
                    uint16_t long_flag = (instr >> 11) & 1; // The long flag is the bit after the PC offset. Shift by 11 to get the bit after the PC offset.
                    reg[R_R7] = reg[R_PC]; 
                    if (long_flag)
                    {
                        uint16_t long_pc_offset = instr & 0x7FF; // The long PC offset is the 11 bits after the opcode. Mask with 0x7FF to get the 11 bits.
                        sign_extend(&long_pc_offset, 11);
                        reg[R_PC] += long_pc_offset; // Jump to the address in the long PC offset
                    }
                    else 
                    {
                        uint16_t r1 = (instr >> 6) & 0x7; // The base register is the 3 bits after the opcode. Shift by 6 to get the 3 bits.
                        reg[R_PC] = reg[r1]; // Jump to the address in the base register
                    }
                }
                break;

            case OP_LD: // Load a value from memory into a register
                {
                    uint16_t r0 = (instr >> 9) & 0x7;
                    uint16_t pc_offset = instr & 0x1FF;
                    sign_extend(&pc_offset, 9);
                    reg[r0] = mem_read(reg[R_PC] + pc_offset);
                    update_flags(r0);
                }
                break;

            case OP_LDI: // Load a value from memory into a register, then load a value from memory into the register specified by the first value
                {
                    uint16_t r0 = (instr >> 9) & 0x7;
                    uint16_t pc_offset = instr & 0x1FF;
                    sign_extend(&pc_offset, 9);
                    reg[r0] = mem_read(mem_read(reg[R_PC] + pc_offset));
                    update_flags(r0);
                }
                break;

            case OP_LDR: // Load a value from memory into a register, then add an offset to the register. Meaning the value is loaded from a memory address that is the sum of the register value and the offset.
                {
                    uint16_t r0 = (instr >> 9) & 0x7;
                    uint16_t r1 = (instr >> 6) & 0x7;
                    uint16_t offset = instr & 0x3F;
                    sign_extend(&offset, 6);
                    reg[r0] = mem_read(reg[r1] + offset);
                    update_flags(r0);
                }
                break;

            case OP_LEA:
                {
                    uint16_t r0 = (instr >> 9) & 0x7;
                    uint16_t pc_offset = instr & 0x1FF;
                    sign_extend(&pc_offset, 9);
                    reg[r0] = reg[R_PC] + pc_offset;
                    update_flags(r0);
                }
                break;

            case OP_ST:
                {
                    uint16_t r0 = (instr >> 9) & 0x7;
                    uint16_t pc_offset = instr & 0x1FF;
                    sign_extend(&pc_offset, 9);
                    mem_write(reg[R_PC] + pc_offset, reg[r0]);
                }
                break;

            case OP_STI:
                {
                    uint16_t r0 = (instr >> 9) & 0x7;
                    uint16_t pc_offset = instr & 0x1FF;
                    sign_extend(&pc_offset, 9);
                    mem_write(mem_read(reg[R_PC] + pc_offset), reg[r0]);
                }
                break;

            case OP_STR:
                {
                    uint16_t r0 = (instr >> 9) & 0x7;
                    uint16_t r1 = (instr >> 6) & 0x7;
                    uint16_t offset = instr & 0x3F;
                    sign_extend(&offset, 6);
                    mem_write(reg[r1] + offset, reg[r0]);
                }
                break;

            case OP_TRAP:
                reg[R_R7] = reg[R_PC];

                switch (instr & 0xFF)
                {
                    case 0x20: //GETC
                        /* read a single ASCII char */
                        reg[R_R0] = (uint16_t)getchar();
                        update_flags(R_R0);
                        break;

                    case 0x21: //OUT
                        putc((char)reg[R_R0], stdout);
                        fflush(stdout);
                        break;

                    case 0x22: //PUTS
                        {
                            uint16_t* c = memory + reg[R_R0];
                            while (*c)
                            {
                                putc((char)*c, stdout);
                                ++c;
                            }
                            fflush(stdout);
                        }
                        break;

                    case 0x23: //IN
                        {
                            printf("Enter a character: ");
                            char c = getchar();
                            putc(c, stdout);
                            fflush(stdout);
                            reg[R_R0] = (uint16_t)c;
                            update_flags(R_R0);
                        }
                        break;

                    case 0x24: //PUTSP
                        {
                            uint16_t* c = memory + reg[R_R0];
                            while (*c)
                            {
                                char char1 = (*c) & 0xFF;
                                putc(char1, stdout);
                                char char2 = (*c) >> 8;
                                if (char2) putc(char2, stdout);
                                ++c;
                            }
                            fflush(stdout);
                        }
                        break;

                    case 0x25: //HALT
                        puts("HALT");
                        fflush(stdout);
                        running = 0;
                        break;
                    
                }
                break;
            case OP_RES:
            case OP_RTI:
            default:
                abort();
                break;    
        }
    }
    restore_input_buffering();
}
