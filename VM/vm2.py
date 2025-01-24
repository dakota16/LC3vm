from enum import Enum, IntFlag
import ctypes
import ctypes.wintypes
from ctypes.wintypes import HANDLE, DWORD
import struct
import sys
import signal


R_R0 = 0
R_R1 = 1
R_R2 = 2
R_R3 = 3
R_R4 = 4
R_R5 = 5
R_R6 = 6
R_R7 = 7
R_PC = 8
R_COND = 9
R_COUNT = 10
    
FL_POS = 1 << 0
FL_ZRO = 1 << 1
FL_NEG = 1 << 2
    
# Opcode constants
OP_BR = 0b0000  # Branch
OP_ADD = 0b0001  # Add
OP_LD = 0b0010  # Load
OP_ST = 0b0011  # Store
OP_JSR = 0b0100  # Jump to Subroutine
OP_AND = 0b0101  # Bitwise AND
OP_LDR = 0b0110  # Load Base+Offset
OP_STR = 0b0111  # Store Base+Offset
OP_RTI = 0b1000  # Unused
OP_NOT = 0b1001  # Bitwise NOT
OP_LDI = 0b1010  # Load Indirect
OP_STI = 0b1011  # Store Indirect
OP_JMP = 0b1100  # Jump
OP_RES = 0b1101  # Reserved (Unused)
OP_LEA = 0b1110  # Load Effective Address
OP_TRAP = 0b1111  # Execute Trap
    
class MemoryMappedRegisters(Enum):
    MR_KBSR = 0xFE00
    MR_KBDR = 0xFE02
    
# Trap codes
TRAP_GETC = 0x20
TRAP_OUT = 0x21
TRAP_PUTS = 0x22
TRAP_IN = 0x23
TRAP_PUTSP = 0x24
TRAP_HALT = 0x25
    
MEMORY_MAX = 65536
memory = [0] * (MEMORY_MAX + 1)
reg = [0] * 10

INVALID_HANDLE_VALUE = HANDLE(-1).value

hStdin = DWORD(INVALID_HANDLE_VALUE)
fdwMode = DWORD(0)
fdwOldMode = DWORD(0)

STD_INPUT_HANDLE = -10
ENABLE_ECHO_INPUT = 0x0004
ENABLE_LINE_INPUT = 0x0002
INVALID_HANDLE_VALUE = HANDLE(-1).value
WAIT_OBJECT_0 = 0x00000000
WAIT_TIMEOUT = 0x00000102

GetStdHandle = ctypes.windll.kernel32.GetStdHandle
GetConsoleMode = ctypes.windll.kernel32.GetConsoleMode
SetConsoleMode = ctypes.windll.kernel32.SetConsoleMode
FlushConsoleInputBuffer = ctypes.windll.kernel32.FlushConsoleInputBuffer
GetStdHandle = ctypes.windll.kernel32.GetStdHandle
_kbhit = ctypes.windll.msvcrt._kbhit
WaitForSingleObject = ctypes.windll.kernel32.WaitForSingleObject
hStdin = GetStdHandle(STD_INPUT_HANDLE)

def disable_input_buffering():
    hStdin = GetStdHandle(STD_INPUT_HANDLE)
    if hStdin == INVALID_HANDLE_VALUE:
        raise ctypes.WinError(ctypes.get.last_error())
    
    fdwOldMode = DWORD()
    if not GetConsoleMode(hStdin, ctypes.byref(fdwOldMode)):
        raise ctypes.WinError(ctypes.get.last_error())
    
    fdwMode = DWORD(fdwOldMode.value & ~(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT))
    if not SetConsoleMode(hStdin, fdwMode):
        raise ctypes.WinError(ctypes.get.last_error())
    
def restore_input_buffering():
    SetConsoleMode(hStdin, fdwOldMode)
    
def check_key():
    wait_result = WaitForSingleObject(hStdin, 1000)
    if wait_result == WAIT_OBJECT_0 and _kbhit():
        return True
    return False

def handle_interrupt(signum, frame):
    restore_input_buffering()
    print()
    exit(-2)
    
def sign_extend(x: int, bit_count: int) -> int:
    sign_bit_mask = 1 << (bit_count - 1)
    extension_mask = 0xFFFF << bit_count
    
    if x & sign_bit_mask:
        x |= extension_mask
        
    return x

def swap16(x: int) -> int:
    return (x << 8) & 0x00FF | (x >> 8) & 0x00FF

def update_flags(r: int):
    if reg[r] == 0:
        reg[R_COND] = FL_ZRO
    elif reg[r] >> 15:
        reg[R_COND] = FL_NEG
    else:
        reg[R_COND] = FL_POS
        
def read_image_file(file_path, origin_override=None):
    try:
        print(f"Attempting to load image: {file_path}")
        with open(file_path, 'rb') as file:
            # Read origin (first 2 bytes)
            origin_bytes = file.read(2)
            if len(origin_bytes) < 2:
                print("Error: Cannot read origin bytes")
                raise ValueError("Invalid image file")
            
            # Unpack origin address
            origin = struct.unpack('<H', origin_bytes)[0]
            origin = swap16(origin)
            
            # Override the origin address if specified
            if origin_override is not None:
                origin = origin_override
            
            print(f"Image origin address: 0x{origin:04X}")
            
            # Track how many words are loaded
            words_loaded = 0
            p = origin
            max_read = MEMORY_MAX - origin
            
            while max_read:
                word_bytes = file.read(2)
                if not word_bytes:
                    break
                
                if len(word_bytes) < 2:
                    print("Warning: Incomplete word at end of file")
                    break
                
                word = struct.unpack('<H', word_bytes)[0]
                memory[p] = swap16(word)
                p += 1
                words_loaded += 1
                max_read -= 1
            
            print(f"Loaded {words_loaded} words starting at address 0x{origin:04X}")
            
            return words_loaded > 0
    
    except Exception as e:
        print(f"Error loading image {file_path}: {e}")
        return False

def read_image(file_path, origin_override=None):
    try:
        return read_image_file(file_path, origin_override)
    except Exception as e:
        print(f"Error reading image: {e}")
        return False
    
def mem_write(address: int, val: int):
    memory[address] = val
    
def mem_read(address: int) -> int:
    if address == MemoryMappedRegisters.MR_KBSR.value:
        if check_key():
            memory[MemoryMappedRegisters.MR_KBSR.value] = 1 << 15
            memory[MemoryMappedRegisters.MR_KBDR.value] = ord(sys.stdin.read(1)) 
        else:
            memory[MemoryMappedRegisters.MR_KBSR.value] = 0
    return memory[address]

def execute_opcode(op: int, instr: int):
    global reg, running  # Ensure we can modify the running flag and registers

    if op == OP_ADD:
        r0 = (instr >> 9) & 0x7
        r1 = (instr >> 6) & 0x7
        imm_flag = (instr >> 5) & 0x1
        if imm_flag:
            imm5 = sign_extend(instr & 0x1F, 5)
            reg[r0] = reg[r1] + imm5
        else:
            r2 = instr & 0x7
            reg[r0] = reg[r1] + reg[r2]
        update_flags(r0)
        reg[R_PC] += 1  # Increment PC after ADD

    elif op == OP_AND:
        r0 = (instr >> 9) & 0x7
        r1 = (instr >> 6) & 0x7
        imm_flag = (instr >> 5) & 0x1
        if imm_flag:
            imm5 = sign_extend(instr & 0x1F, 5)
            reg[r0] = reg[r1] & imm5
        else:
            r2 = instr & 0x7
            reg[r0] = reg[r1] & reg[r2]
        update_flags(r0)
        reg[R_PC] += 1  # Increment PC after AND

    elif op == OP_NOT:
        r0 = (instr >> 9) & 0x7
        r1 = (instr >> 6) & 0x7
        reg[r0] = ~reg[r1]
        update_flags(r0)
        reg[R_PC] += 1  # Increment PC after NOT

    elif op == OP_BR:
        cond_flag = (instr >> 9) & 0x7
        pc_offset = sign_extend(instr & 0x1FF, 9)
        if cond_flag & reg[R_COND]:
            reg[R_PC] += pc_offset

    elif op == OP_JMP:
        r1 = (instr >> 6) & 0x7
        reg[R_PC] = reg[r1]  # Jump to the address in R1 (no PC increment)

    elif op == OP_JSR:
        long_flag = (instr >> 11) & 1
        reg[R_R7] = reg[R_PC]  # Save the return address in R7
        if long_flag:
            long_pc_offset = sign_extend(instr & 0x7FF, 11)
            reg[R_PC] += long_pc_offset  # Jump to PC + offset
        else:
            r1 = (instr >> 6) & 0x7
            reg[R_PC] = reg[r1]  # Jump to the address in R1

    elif op == OP_LD:
        r0 = (instr >> 9) & 0x7
        pc_offset = sign_extend(instr & 0x1FF, 9)
        reg[r0] = mem_read(reg[R_PC] + pc_offset)
        update_flags(r0)
        reg[R_PC] += 1  # Increment PC after LD

    elif op == OP_LDI:
        r0 = (instr >> 9) & 0x7
        pc_offset = sign_extend(instr & 0x1FF, 9)
        reg[r0] = mem_read(mem_read(reg[R_PC] + pc_offset))
        update_flags(r0)
        reg[R_PC] += 1  # Increment PC after LDI

    elif op == OP_LDR:
        r0 = (instr >> 9) & 0x7
        r1 = (instr >> 6) & 0x7
        offset = sign_extend(instr & 0x3F, 6)
        reg[r0] = mem_read(reg[r1] + offset)
        update_flags(r0)
        reg[R_PC] += 1  # Increment PC after LDR

    elif op == OP_LEA:
        r0 = (instr >> 9) & 0x7
        pc_offset = sign_extend(instr & 0x1FF, 9)
        reg[r0] = reg[R_PC] + pc_offset
        update_flags(r0)
        reg[R_PC] += 1  # Increment PC after LEA

    elif op == OP_ST:
        r0 = (instr >> 9) & 0x7
        r1 = (instr >> 6) & 0x7
        offset = sign_extend(instr & 0x3F, 6)
        mem_write(reg[r1] + offset, reg[r0])
        reg[R_PC] += 1  # Increment PC after ST

    elif op == OP_STI:
        r0 = (instr >> 9) & 0x7
        pc_offset = sign_extend(instr & 0x1FF, 9)
        mem_write(mem_read(reg[R_PC] + pc_offset), reg[r0])
        reg[R_PC] += 1  # Increment PC after STI

    elif op == OP_STR:
        r0 = (instr >> 9) & 0x7
        r1 = (instr >> 6) & 0x7
        offset = sign_extend(instr & 0x3F, 6)
        mem_write(reg[r1] + offset, reg[r0])
        reg[R_PC] += 1  # Increment PC after STR

    elif op == OP_TRAP:
        trap_vector = instr & 0xFF
        if trap_vector == TRAP_GETC:
            reg[R_R0] = ord(input())
            
        elif trap_vector == TRAP_OUT:
            print(chr(reg[R_R0]))
            
        elif trap_vector == TRAP_PUTS:
            address = reg[R_R0]
            while True:
                char = mem_read(address)
                if char == 0:
                    break
                print(chr(char))
                address += 1
        
        elif trap_vector == TRAP_IN:
            print("Enter a character: ")
            reg[R_R0] = ord(input())
        
        elif trap_vector == TRAP_PUTSP:
            address = reg[R_R0]
            while True:
                char = mem_read(address)
                if char == 0:
                    break
                print(chr(char), end='')
                address += 1
       
        elif trap_vector == TRAP_HALT:
            print("HALT")
            running = False
            return  # Do not increment PC after HALT
        
        elif op == OP_RES or op == OP_RTI:
            print("Invalid opcode")
            exit(1)
        reg[R_PC] += 1  # Increment PC after TRAP (except for HALT)

    else:
        print(f"Unknown opcode: {op}")
        running = False
    
def main():
    global reg, running
    
    argc = len(sys.argv)
    argv = sys.argv
    
    if argc < 2:
        print("lc3 [image-file1] ...")
        exit(2)
        
    for i in range(1, argc):
        if not read_image(argv[i]):  # Load the image without overriding the origin
            exit(1)
            
    disable_input_buffering()
    signal.signal(signal.SIGINT, handle_interrupt)
    
    # Initialize the condition flag (R_COND) to FL_ZRO
    reg[R_COND] = FL_ZRO
    
    # Set the program counter (R_PC) to the starting address (0x3000)
    PC_START = 0x3000  # The program counter starts at 0x3000
    reg[R_PC] = PC_START
    
    running = True
    while running:
        # Debug: Print the current PC and instruction
        print(f"PC: 0x{reg[R_PC]:04X}, Instruction: 0x{mem_read(reg[R_PC]):04X}")
        
        # Stop execution if PC exceeds memory bounds
        if reg[R_PC] < 0 or reg[R_PC] >= MEMORY_MAX:
            print("Error: Program counter out of bounds")
            running = False
            break
        
        # Fetch and increment PC
        instr = mem_read(reg[R_PC])
        reg[R_PC] += 1

        # Decode and execute instruction
        op = instr >> 12
        try:
            execute_opcode(op, instr)
        except Exception as e:
            print(f"Error executing instruction: {e}")
            running = False
            
    restore_input_buffering()
    
if __name__ == "__main__":
    main()
    
    
    
    
    
                
                
        
        
        