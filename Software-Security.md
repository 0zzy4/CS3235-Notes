# Software Security - Lectures 2 & 3 Notes

# Lecture 2: Software Security 1

## Buffer Overflows - Fundamentals

### What is a Buffer Overflow?

A buffer overflow occurs when more data is written to a buffer than it can hold, causing the extra data to overwrite adjacent memory locations on the stack.

**Classic Example:**
```c
#include <string.h>
void foo(char *str) {
    char buffer[4];
    strcpy(buffer, str);  // No bounds checking!
}

int main() {
    char *str = "1234567890!?ABCDEFG";
    foo(str);
}
```

In this example:
- `buffer[4]` can only hold 4 characters
- `strcpy()` copies the entire string (19+ characters) into the 4-byte buffer
- The overflow overwrites adjacent stack memory including:
  - Saved frame pointer (RBP)
  - Return address (RIP)
  - Other stack data

### Types of Buffer Overflow Vulnerabilities

**1. User Input Buffer Overflow**
```c
void welcome_user(){
    char buffer[100];
    printf("Enter name: ");
    gets(buffer);  // Dangerous! No bounds checking
    printf("Hello, %s!\n", buffer);
}
```
Exploit: `$ python -c "print('a' * 1024)" | ./a.out`

**2. Network Input Buffer Overflow**
```c
int getField(int socket, char* field){
    int fieldLen = 0;
    read(socket, &fieldLen, 4);
    read(socket, field, fieldLen);  // Trusts attacker-controlled length!
    return fieldLen;
}
```
Exploit: `$ python -c "print('\x00\x01\x00\x00' + 'a'*65536)" | nc <IP> <PORT>`

### Stack Structure During Buffer Overflow

Stack grows from high addresses to low addresses:

```
High Address (0xFFFFFFFFFFFFFFFF)
┌─────────────────┐
│      ...        │
├─────────────────┤
│   Saved RIP     │ ← Return address (gets overwritten!)
├─────────────────┤
│   Saved RBP     │ ← Frame pointer (gets overwritten!)
├─────────────────┤
│   ptr to argv[1]│
├─────────────────┤
│  <Space for     │
│   MyVar>        │ ← Buffer starts here
├─────────────────┤ ← RSP points here (top of stack)
│      ...        │
Low Address (0x0000000000000000)
```

When `strcpy()` copies data:
1. Fills the buffer
2. Continues writing, overwriting saved RBP
3. Overwrites saved RIP (return address)
4. When function returns, jumps to attacker-controlled address!

## Stack Shellcode Attack

**Goal:** Instead of just crashing, execute arbitrary code with the program's privileges.

### Three Steps to Stack Shellcode:
1. **Compile your own code** to be executed (the "shellcode")
2. **Inject that code** into the application (via buffer overflow)
3. **Redirect control** to your binary instructions

### Simple Shellcode Example

```c
int main() {
    target_label:
    goto target_label;  // Infinite loop
}
```

Compiles to:
```asm
main()
0000000000401749 55        PUSH RBP
000000000040174a 48 89 e5  MOV RBP,RSP
target_label
00000000000111b4 eb fe     JMP target_label  ; This is the shellcode!
```

The bytes `eb fe` represent the infinite loop shellcode.

### Stack Layout for Shellcode Attack

**Before overflow (Good):**
```
prev FP
str_ptr
str_ptr
return
main FP
buffer
```

**After overflow (Evil):**
```
prev FP
str_ptr
0x00000000FFFF8888  ← Address of shellcode
0x4141414141414141  ← Part of overflow
0xEBFE414141414141  ← Shellcode bytes (eb fe = JMP)
str_ptr
```

When the function returns:
- Pops the return address (now pointing to shellcode location)
- Jumps to that address
- Executes attacker's shellcode with program's privileges!

### Privilege Context
**Critical Security Note:** Shellcode executes with the **host program's privileges**. If the program runs as root or a system service, the attacker gains those privileges!

**Principle of Least Privilege is IMPORTANT!**

### Shellcode Caveats

**1. "Forbidden" Characters**

Different functions have characters they treat specially:
- `strcpy()`: Cannot contain `0x00` (null byte)
- `gets()`: Cannot contain `\n` (newline)
- `scanf()`: Cannot contain any whitespace

Attackers must craft shellcode avoiding these bytes (heavily dependent on the vulnerability).

**2. Hard to Guess Addresses**

Two challenges:
- **Shellcode address**: Where is the code I injected?
- **Return address**: Where do I tell the CPU my code is?

**Solution: NOP Sled**
```
Stack layout:
┌──────────────┐
│   ret guess  │ ← Multiple guesses at return address
│   ret guess  │
│   ret guess  │
│      ...     │
│     nop      │ ← NOP sled (no operation instructions)
│     nop      │
│     ...      │
│   shellcode  │ ← Actual malicious code
│    ?buff?    │
│    ?buff?    │
└──────────────┘
```

The NOP sled increases chances of hitting valid code - any address in the NOP region will "slide" down to the shellcode.

## Vulnerability vs Exploit - Three Step Process

**Review of exploitation steps:**
1. **Find vulnerable code** (e.g., uncontrolled write like `strcpy`)
2. **Inject shellcode** into the application (any commands attacker wants)
3. **Redirect control** to your shellcode (via overwritten return address)

---

## Cat-and-Mouse Game: Defenses and Counter-Attacks

This is an ongoing battle between defenders (adding protections) and attackers (finding ways around them).

## The Exploitation Techniques Toolbox

```
Attack Chain:
Buffer Overflow
  → Stack Shellcode
    → DEP (Defense)
      → Data-only attacks
      → Return-to-libc
        → Extraneous function removal (Defense)
          → ROP (Return Oriented Programming)
            → ASLR (Defense)
              → Stack Canaries (Defense)
                → Buffer Over-read
                  → Integer Overflow
                    → Automated Testing (Both sides use it!)
```

---

## Lecture 3: Software Security 2

## Defense 1: Data Execution Prevention (DEP)

### The Problem
Defender's problem: **Data and code are the same thing** on traditional systems.

### The Solution
**Write ⊕ Execute** (Write XOR Execute)
- Memory regions marked as **writable** (heap/stack) OR **executable** (code segments)
- **Never both!**
- Enforced by hardware or OS

### How DEP Works

When attacker tries to execute shellcode on the stack:

```
Stack contains shellcode:
0x00000000ffff8888
prev FP
str_ptr
0x00000000FFFF8888
0x4141414141414141
0xEBFE414141414141  ← Try to execute this
str_ptr
```

**Result:**
```
OS ERROR: CONTROL FLOW IS INCORRECT
→ IMMEDIATELY END PROCESS
```

The OS detects execution from a non-executable region and kills the process.

---

## Attack 1: Data-Only Attacks

**Attacker's Response:** "If I can't execute code, I'll just modify data to change program behavior!"

### Example: Account Deletion Function

```c
int delete_account(char* username, int length, VOID* creds) {
    int allowed;
    char name[100];
    allowed = check_cred(creds);  // Returns 0 (not authorized)
    strncpy(name, username, length);
    canonicalize_username(name);
    if (allowed) {delete_user(name);}  // Only runs if allowed != 0
    return (allowed > 0);
}
```

**Normal Stack Layout:**
```
return
main FP
allowed: 0      ← User is NOT authorized
...
...
name
```

**After Buffer Overflow:**
```
return
...
main FP
allowed: 1      ← Overwritten to 1 (authorized!)
...
0
victim          ← Username to delete
```

**Attack Result:**
- Overflow the `name` buffer
- Overwrite the `allowed` variable to 1
- Never executed any code, just changed data
- Function deletes the victim's account even though attacker wasn't authorized!

---

## Attack 2: Return-to-libc

**Context:** DEP prevents executing injected shellcode, but what about code that's already in the binary?

### What is libc?
- **libc** = C standard library
- Contains common functions like `strcpy`, `printf`, `execv`
- Already marked as **executable** in memory
- Present in almost every C program

### The Attack Strategy

**Attacker:** "I'll reuse code that already exists - it's already marked as executable!"

Make the stack look like a normal function call to a libc function.

### Return-to-libc Stack Setup

**Normal Function Call Setup:**
```
local var
return       ← Return address
[arguments]  ← Function arguments below return address
```

**Return-to-libc Attack Setup:**
```
local var
local var/pad
return/func ptr    ← Address of libc function (e.g., execv)
saved FP/pad
buffer/pad
buffer/arg1        ← Arguments for the function
pad
```

**Key Point:** "Code at func ptr will assume the stack is setup for a function call!"

### Setting Up Registers

Before calling a libc function, need to set registers properly:
- In x86-64, function arguments go in: `rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9`
- **Solution:** Use ROP gadgets (explained later) to set these registers
- Place arguments on the stack

### Popular Target: execv()

```c
int main() {
    char* args[] = {"/bin/ls", NULL};
    execv("/bin/ls", args);
}
```

This function executes shell commands - perfect for attacker to gain shell access!

**Stack for execv call:**
```
prev FP
[args array]      ← Pointer to command arguments
["/bin/ls" string]
[Address of execv function]
```

---

## Defense 2: Extraneous Function Removal

**Defender:** "The attackers are calling other functions. Let's remove functions we don't need!"

Remove dangerous libc functions like `execv()`, `system()` from the binary during compilation.

---

## Attack 3: Return-Oriented Programming (ROP)

**Attacker:** "You removed dangerous functions? I'll use the instructions that are still there!"

### What is ROP?

**Return-Oriented Programming:**
- "Return to libc without calling full functions"
- Build arbitrary functionality via "gadgets"
- **Turing complete** (can compute anything!)

### What is a ROP Gadget?

A gadget is a:
1. **Small section of code** (1-5 instructions)
2. **Ends in `ret`** instruction (0xC3 byte)
3. **Not an existing function body** - just fragments

### Finding Gadgets

**Key insight:** x86 has **variable-length instructions** - the "achilles heel of x86"

From a single byte sequence, you can find multiple gadgets by starting at different offsets!

**Example byte sequence:**
```
00 F7 48 C7 C7 00 00 00 0F 48 95 48 FF C5 C3
```

Depending on where you start reading, you get different instructions:
- Start at end: `ret` (just 0xC3)
- Start earlier: `inc rbp; ret`
- Start even earlier: `xchg rbp,rax; inc rbp; ret`
- Start at beginning: `mov rdi,0xf000000; xchg rbp,rax; inc rbp; ret`

**From existing function code:**
```c
int foo(int a, int b) {
    a -= 10;
}
```

Compiles to:
```asm
foo:
push rbp
mov rbp,rsp
mov DWORD PTR [rbp-0x4],edi
mov DWORD PTR [rbp-0x8],esi
sub DWORD PTR [rbp-0x4],0xa
nop
pop rbp
ret
```

**Gadget extracted (at foo+0x10):**
```asm
sub DWORD PTR [rbp-0x4],0xa
nop
pop rbp
ret
```

**Statistic:** About 1 in every 178 bytes can be part of a useful ROP gadget.

### ROP Chains - Chaining Gadgets Together

**Example gadgets:**
```asm
Gadget1: mov rax, 0x10; ret
Gadget2: add rax, rbp; ret
Gadget3: mov [rax+8], rax; ret
Gadget4: mov rbp, rsp; ret
```

**Stack setup for ROP chain:**
```
*gadget1      ← Vulnerable function returns here
pad
pad
*gadget2      ← After gadget1's ret
*gadget2      ← Can call same gadget multiple times!
*gadget3
*gadget4
```

**Execution flow:**
1. Vulnerable function executes `ret` → jumps to gadget1
2. Gadget1 executes: `mov rax, 0x10; ret`
3. Gadget1's `ret` pops next address from stack → jumps to gadget2
4. Gadget2 executes: `add rax, rbp; ret`
5. Gadget2's `ret` → jumps to gadget2 again (reuse!)
6. Continue through chain...

**Final result is effectively:**
```asm
mov rax, 0x10
add rax, rbp
add rax, rbp
mov [rax+8], rax
mov rbp, rsp
```

### Why It's Called "Return-Oriented"
Everything chains together through `ret` instructions! Each gadget ends with `ret`, which:
- Pops an address off the stack
- Jumps to that address

By controlling what's on the stack, attacker controls which gadgets execute in sequence.

### ROP Tips (from appsec_primer)
- **What does `pop` do?** Takes what's at top of stack and puts it into a register (e.g., `pop rax`)
- **Make sure all gadgets end in `ret`** - this is what chains them together
- **Use Ctrl-F or grep** to search through binary for useful gadgets
- **Gadgets can affect the stack/each other** - watch for side effects!
- **Good idea:** Include `/bin/sh` string in your payload instead of searching for it in the binary
- **The `ret` instruction is byte `0xC3`**

---

## Defense 3: Address Space Layout Randomization (ASLR)

**Defender:** "We can't take out all the rets from our code. Let's move around where the code lives!"

### What is ASLR?

**Address Space Layout Randomization:**
- Makes it extremely hard to predict memory addresses
- Randomizes locations of:
  - Stack
  - Heap
  - Code sections
  - libc library
- Code must be "relocatable" or "position independent"

### Memory Layout Without ASLR

**Same every time the program runs:**
```
0xFFFFFFFFFFFFFFFF (High)
┌────────────┐
│   stack    │ ← Always at same address
├────────────┤
│   libc     │ ← Always at same address
├────────────┤
│ code sect  │ ← Always at same address
├────────────┤
│   heap     │ ← Always at same address
└────────────┘
0x0000000000000000 (Low)
```

Every execution has identical memory layout - attacker knows exactly where to jump!

### Memory Layout With ASLR

**Different each time:**
```
Run 1:              Run 2:              Run 3:
┌────────────┐      ┌────────────┐      ┌────────────┐
│   stack    │      │ code sect  │      │   heap     │
├────────────┤      ├────────────┤      ├────────────┤
│   libc     │      │   libc     │      │   stack    │
├────────────┤      ├────────────┤      ├────────────┤
│ code sect  │      │   stack    │      │   libc     │
├────────────┤      ├────────────┤      ├────────────┤
│   heap     │      │   heap     │      │ code sect  │
└────────────┘      └────────────┘      └────────────┘
```

Addresses randomized on each execution - attacker can't predict where to jump!

### Defeating ASLR

**Hint from slides:** "All of libc is at a single offset. Over-read a single pointer in libc!"

If attacker can **leak a single address** from libc:
- Can calculate offset of entire libc section
- All functions in libc are at predictable offsets from each other
- One leak compromises the whole library!

### ASLR Limitations

**From slides:**
- **Everything must be relocatable** to be effective
- **A single code section that can be referenced** may provide enough ROP gadgets for exploitation
- **Attacker may disclose the offset of an entire chunk!**
- **Fine-grained ASLR** shuffles code within the chunks (more protection)

---

## Defense 4: Stack Canaries

**Defender:** "Attackers keep overwriting return addresses! We shall protect the return address! Keep a canary in the coal mine!"

### How Stack Canaries Work

**On function call:**
```
return
main FP
canary ← Secret value placed here
...
buffers
```

The "canary" is a secret random value placed on the stack between local buffers and the return address.

**During execution:**
```
return
main FP
canary
... buffers ← Normal buffer usage
```

**After buffer overflow:**
```
0x414141411414141  ← Overflow overwrites everything
0x414141411414141
0x41414141         ← Canary got overwritten!
AAAAAAA...
```

**On function return:**
```asm
# on leave:
if canary != expected:
    goto stack_chk_fail  # Abort!
return
```

**Result:**
```
*** stack smashing detected ***
```

Program detects the canary was modified and terminates before attacker can exploit the overwritten return address.

### Limitations

Canaries protect the return address, but don't stop:
- Data-only attacks (overwriting local variables)
- Buffer over-reads (reading beyond buffer bounds)

---

## Attack 4: Buffer Over-Read

**Example: Heartbleed Vulnerability**

Famous real-world vulnerability that leaked sensitive data from servers.

### Vulnerable Code Pattern

```c
int sendField(int socket, char* field){
    int fieldLen = 0;
    read(socket, &fieldLen, 4);        // Attacker controls this!
    write(socket, field, fieldLen);    // Writes fieldLen bytes
    return fieldLen;
}
```

**The problem:** Attacker controls `fieldLen` but code doesn't verify it's legitimate.

### Stack Layout

**Normal operation:**
```
return
main FP
canary
buffers
```

**When attacker sends huge fieldLen:**
```
return      ← Reads and sends this back to attacker!
main FP     ← Reads and sends this back to attacker!
canary      ← Reads and sends this back to attacker!
buffers     ← Reads beyond buffer bounds
```

**Result:**
- Reads beyond buffer boundaries
- Sends sensitive data (including canary, return addresses, other secrets) back to attacker
- **Doesn't modify anything** - just reads, so canary doesn't detect it!

**On return:**
```asm
# on return:
if canary != expected:
    goto stack_chk_fail
return  # Canary is still intact! No detection!
```

---

## Integer Overflow (mentioned in toolbox)

Referenced as part of exploitation techniques, with reading material: "Blexim's Basic Integer Overflows"

---

## Automated Testing (Both Attack and Defense)

**The Problem:** Vulnerabilities are hard to find by hand.

**Both defenders and attackers use automated tools!**

## Why Automation?

**Finding vulnerabilities manually is very hard:**
- If source is available: Tons of potential vulnerabilities in code base
- If closed source: Reverse engineering is laborious

## Types of Automated Testing Tools

### 1. Memory Analysis Tools
**Purpose:** Finding memory leaks and access violations

**How it works:**
- Execute in a virtual environment
- Perform dynamic run-time checks

**Checks for:**
- Does the program access uninitialized memory?
- Does the program use memory after it's free'd? (use-after-free)

### 2. Static Analysis Tools
**Purpose:** Look for dangerous coding patterns

**How it works:**
- Analyze source code without executing
- Usually requires complete source code

**Checks for:**
- Are integers mixing signed and unsigned usage?
- Are all variables initialized when declared?
- Use of dangerous functions like `strcpy`, `gets`

**Drawback:** Large number of false-positives

### 3. Taint Analysis Tools
**Purpose:** Trace value usage throughout code

**How it works:**
- Mark untrusted input as "tainted"
- Track how tainted data flows through program

**Checks for:**
- Is a user-supplied value used to index an array?
- Is an unsafe value used to shell-out?
- Does tainted data reach sensitive operations?

### 4. Fuzzers
**Purpose:** "Brute Force Testing"

**How it works:**
- Generate random or semi-random inputs
- Monitor program's behavior for crashes
- More advanced versions optimize for code coverage

**Test questions:**
- If I give you really long strings, will you crash?
- If I give you random data, will you crash?
- If I give you broken formats, will you crash?

---

## General Defenses Against Buffer Overflow Attacks

## Programming Language Choice

**The language should:**
- **Be strongly typed** (Java, Python, Rust, etc.)
- **Do automatic bounds checks** (Java, Python, Rust, etc.)
- **Do automatic memory management** (garbage collection)

**Why are some languages safe?**
- Buffer overflow becomes **impossible** due to runtime system checks
- Array access is validated before allowing
- Memory is managed automatically

**Drawback:**
- Possible **performance degradation**
- Runtime checks add overhead

## When Using Unsafe Languages (C/C++)

**Best practices:**
1. **Check ALL input** (ALL input is EVIL!)
2. **Use safer functions** that do bounds checking:
   - Use `strncpy()` instead of `strcpy()`
   - Use `fgets()` instead of `gets()`
   - Use `snprintf()` instead of `sprintf()`
3. **Use automatic tools** to analyze code for potential unsafe functions

---

## Summary: The Cat-and-Mouse Game

**The Complete Exploit Chain:**

1. **Buffer Overflow** → Crash or control hijacking
2. **Stack Shellcode** → Execute arbitrary code
3. **DEP Defense** → Marks stack non-executable
4. **Data-only attacks** → Bypass DEP by modifying data, not code
5. **Return-to-libc** → Reuse existing executable code
6. **Function removal** → Remove dangerous functions
7. **ROP** → Chain small gadgets together
8. **ASLR** → Randomize memory layout
9. **Stack Canaries** → Detect stack corruption
10. **Buffer Over-read** → Leak data without modification
11. **Integer Overflow** → Cause unexpected behavior
12. **Automated Testing** → Find vulnerabilities faster

This is an ongoing arms race between security researchers and attackers!

---

## Further Reading

Recommended resources from the lectures:

1. **Aleph One's "Smashing the Stack for Fun and Profit"**
   http://insecure.org/stf/smashstack.html

2. **Paul Makowski's "Smashing the Stack in 2011"**
   http://paulmakowski.wordpress.com/2011/01/25/smashing-the-stackin-2011/

3. **Blexim's "Basic Integer Overflows"**
   http://www.phrack.org/issues.html?issue=60&id=10

4. **Return-to-libc demo**
   http://www.securitytube.net/video/258

---

## Key Takeaways

1. **Buffer overflows** are caused by writing more data than a buffer can hold
2. **Stack layout** is critical - understanding RSP, RBP, and return addresses is fundamental
3. **Defenses and attacks evolve together** in a cat-and-mouse game
4. **DEP, ASLR, and Stack Canaries** are major defense mechanisms still in use today
5. **ROP is powerful** - can build arbitrary functionality from existing code fragments
6. **Language choice matters** - memory-safe languages prevent entire classes of vulnerabilities
7. **All input is evil** - never trust user input, always validate and sanitize