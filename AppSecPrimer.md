## CPU Registers in x86 (64 bit)
- `rsp` = stack pointer
	- points to top (lowest address) of current stack frame
- `rbp` = bottom stack pointer, aka frame pointer
	- points to bottom (highest address) of current stack frame
	- used to reference function parameters & local variables
- `rip` = instruction pointer (`pc` in LC3200)
	- points to the next instruction to be executed
- `rax`, `rbx`, `rcx`, `rdx`, `rdi`, `rsi` = temporary data storage
## x86 Calling Convention

```
TOP of stack (LOW addresses)
├─────────────────────────┐
│ callee local variables  │ ← RSP points here
├─────────────────────────┤
│ Saved RBP (caller's FP) │ ← RBP points HERE ✓
├─────────────────────────┤
│ Return address          │ ← This is at RBP + 8
├─────────────────────────┤
│ callee's arguments      │ ← These start at RBP + 16
├─────────────────────────┤
│ caller's local variables│
└─────────────────────────┘
BOTTOM of stack (HIGH addresses)
```
## Stack Frame example
```c
void foo()
{
	char buf1[16]
}

int _main()
{
    foo();
}
```
Steps
1. Push `main`'s local variables onto the stack
2. Prepare for call to `foo` push `foo`'s arguments onto the stack
3. Push the return address (RIP) and main’s frame pointer (RBP) on the stack
	- return address - so CPU knows where to continue execution after returning from `foo`
	- `main`'s frame pointer - so can return to `main`'s frame after `foo` teardown
4. Move FP (RBP) to begin a new stack frame for `foo` (`mov rbp, rsp`)
5. Push `foo`’s variables on the stack
6. Teardown of `foo`
	1. `leave` instruction
		- `mov rsp, rbp` - deallocate local variables (reset stack pointer)
		- Use `pop rbp` instruction to:
		    - **Loads** the value at RSP (which is main's saved FP) **into** the RBP register
		    - **Then** increments RSP by 8 (removing it from stack)
	2. Use `ret` instruction to:
	    - Pops the return address into RIP
	    - Jumps to that address
## Buffer Overflows

- `strcpy`
	- has no bounds to what it copies, just copies to the stack until it reaches a null byte
	- copies from lower to higher memory address
- Therefore, if the input for the `strcpy` function is greater than the size of the buffer, then `strycpy` will end up overwriting what's in the stack (bc copies lower to higher addresses)
- This means we can craft an input to allow the function with the `strcpy` to return wherever we want
## CPU Instructions
- Move a value to a register
	- ` mov rax, 0x34` (this is Intel syntax)
	- Two assembly syntax: Intel & AT&T
- Add a value to a register
	- `add rax, 10`
- Change execution path
	- `jump`
	- `call`
it's the callee's responsibility to handle the previous frame pointer

need to put foo's arguments from stack / memory into registers to be able to work with them. that's what the DWORD lines do

`strcpy` doesn't care about how long it's copying, just does it even if it overwrites other addresses

## GDB
- Memory Addresses vs Content
	- Memory addresses = 64 bits (tells you WHERE)
	- Memory contents = 1 byte per address (tells you WHAT)
	- To store 64-bit values, you use 8 consecutive 1-byte memory locations
		- hence why you use `$rbp + 8` when reading an address or pointer
- `disas(semble)` - shows function's code in assembly
- Careful, x86 is little endian!
	- x/64wx $sp => address 0x0: 0x0123456789ABCDEF 0x…..
		- `*0x0 = 0xEF`
		- `*0x1 = 0xCD`
		- `*0x2 = 0xAB`
		- `*0x3 = 0x89`
		- `*0x4 = 0x67`
		- `*0x5 = 0x45`
		- `*0x6 = 0x23`
		- `*0x7 = 0x01`
- `ni` - if next instruction is a function, it doesn't step into next function call
- `si` - does step into next function
- `continue` - continues running until break or end of program
- `r` - runs the program
### Example
```gdb
(gdb) x/120bx $sp
RSP	0x7fffffffe470: 0x40    0x62    0x4c    0x00    0x00    0x00    0x00    0x00
	0x7fffffffe478: 0x71    0xe9    0xff    0xff    0xff    0x7f    0x00    0x00
	0x7fffffffe480: 0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
	0x7fffffffe488: 0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
	0x7fffffffe490: 0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
	0x7fffffffe498: 0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
RBP	0x7fffffffe4a0: 0x00    0xe4    0xff    0xff    0xff    0x7f    0x00    0x00
ret	0x7fffffffe4a8: 0x3c    0x18    0x40    0x00    0x00    0x00    0x00    0x00
	0x7fffffffe4b0: 0xa8    0xe6    0xff    0xff    0xff    0x7f    0x00    0x00
	0x7fffffffe4b8: 0x00    0x00    0x00    0x00    0x00    0x02    0x00    0x00
	0x7fffffffe4c0: 0x01    0x00    0x00    0x00    0x00    0x00    0x00    0x00
	0x7fffffffe4c8: 0x7a    0x1c    0x40    0x00    0x00    0x00    0x00    0x00
	0x7fffffffe4d0: 0x00    0x00    0x00    0x00    0x00    0x20    0x00    0x00
	0x7fffffffe4d8: 0xe6    0x17    0x40    0x00    0x00    0x00    0x00    0x00
	0x7fffffffe4e0: 0x00    0x00    0x00    0x00    0x00    0x02    0x00    0x00
```

#### How to read this
- GDB displays 8 addresses per row, hence why on the left the addresses skip by 8, meaning...
	- `*0x7fffffffe470 = 0x40`
	- `*0x7fffffffe471 = 0x62`
	- `*0x7fffffffe472 = 0x4c`
	- and so on
- `x/120bx` - displays 120 bytes (8 columns x 15 rows) in hexadecimal, starting from the address where the previous instance of this command has finished.
#### Key locations noted in the slide:
- **Stack pointer (RSP):** points to `0x7fffffffe470`
- **Base pointer minus 0x20:** at `0x7fffffffe480` (buffer starts here, where all the 0x41s are)
- **Base pointer (RBP):** points to `0x00007fffffffe400` (saved RBP location)
	- value at the address is `0x7fffffffe4e0`, at the bottom of the stack
- **Return address:** at `0x7fffffffe4a8`
	- value 0x40183c in little-endian
	- value is caller's return address
## Assembly Syntax
### Intel
`add rsp, 0x10`
`lea rax, [rbp-0x1c]`
- Operands ordered as `dest`, `src`
- Commonly used for Windows
- `objdump` -d -M intel `a.out`
### AT&T
`add $0x10, %rsp`
`lea -0x1c(%rbp),%rax`
- Operands ordered as `src`, `dest`
- Commonly used for Linux
- `objdump` -d -M AT&T `ua.ot`

## Note
### GDB Run Error
```gdb
/bin/bash: line 1: /home/cs3235/lab1/appsec_lab: Permission denied
/bin/bash: line 1: exec: /home/cs3235/lab1/appsec_lab: cannot execute: Permission denied
```
1. Quit gbd by typing `q`
2. Use `chmod +x appsec_lab` to give it full execute permissions
3. Enter back into gdb with `gdb appsec_lab`

### How to Use x/
#### Single value at single register:
```gdb
(gdb) x/1bx $rbp+4

0x7fffffffe4a8: 0x5d
```
- `1bx` = 1 byte in hexadecimal
- `$rbp+4` = start at 4 bytes after the address held in RBP


#### Values for addresses at & after register
```gdb
(gdb) x/24bx $rbp

0x7ffffff6ffc8: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x7ffffff6ffd0: 0xe0    0xff    0xf6    0xff    0xff    0x7f    0x00    0x00
0x7ffffff6ffd8: 0x72    0x1d    0x40    0x00    0x00    0x00    0x00    0x00
```
- `24bx` = 24 bytes in hexadecimal
  - displayed by 3 rows of 8 columns, each cell representing the value at each of the 24 addresses
- `$rbp` = start displaying at the addresses held in RBP

#### Endianness
```gdb
(gdb) x/1gx $rsp
(gdb) x/8bx $rsp
```
- `g` = giant word (8 bytes)
  - reads 8 bytes and displays them as a single 64-bit value in big-endian (human-readable format)
- `b` = individual bytes (1 byte each)
  - displays the raw bytes in little-endian order (how they're actually stored in memory)

### Accessing Inner Function's RBP Value
At the beginning of the function, you will see:
```gdb
   0x0000000000401c96:  push    rbp
   0x0000000000401c97:  mov     rbp, rsp
```
- `push rbp` = saves caller's rbp (frame pointer) onto the stack
- `mov rbp, rsp` = sets RBP to the current stack pointer value
  - After `push rbp`, RSP points to where we just saved the old RBP
  - By setting RBP = RSP, now RBP points to the location of the saved RBP
  - This establishes the base of the new stack frame for the callee

**Important:** You must step past the `mov rbp, rsp` instruction before examining the callee's RBP or any values relative to it (like `$rbp+8`).

Before this instruction completes, RBP still points to the caller's frame.
