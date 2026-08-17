# [PIDXploit] - CrackMe Writeup

**Difficulty:** Medium 
**Category:** Reverse Engineering  
**Platform:** Windows 
**Target Architecture:** x86  

## Executive Summary

The objective of the lab is to find the password.

---

## File Information

- **Filename:** PIDXploit.exe
- **SHA-256:** `26560ce47c44d3c17b5f1068c5a9fd3216c2d2a8e1435e62b6f5805ee824c2a3`
- **File Type:** `PE32 executable (console) Intel 80386, for MS Windows`

---

## Tools Used
- **OS:** Linux(REMnux)
- **Disassembler / Decompiler:** Ghidra 
- **Debugger:** Ghidra, gdbserver, gdb 

---

## Walkthrough

### 1. Initial Triage & Static Analysis

Initial static analysis of the binary was performed in Ghidra to map out the application's control flow and locate the key validation routines.

- **Main Entry Point:** `0x0040148B`
- **Password Generation Function (`_generate_password`):** `0x00401460`
- **Key Imports:** `MSVCRT.dll!_getpid`

#### Decompilation & Logic Breakdown

Examining the main function at `0x0040148B` revealed that the executable generates a dynamic validation key at runtime rather than using a hardcoded string. The program calls `_generate_password` at `0x00401460` after to accepting user input.

Inside `_generate_password`, the routine constructs the expected password by concatenating a static string with the active Process ID (PID) fetched via `MSVCRT.dll!_getpid()`:

```c
// Decompiled pseudo-code of _generate_password (0x00401460)
void __cdecl _generate_password(char *param_1)
{
  int iVar1;  
  iVar1 = _getpid();
  _sprintf(param_1,"EndIsNear-%d",iVar1);
  return;
}
```

The resulting string is then passed into a standard comparison function against the user-supplied string. Because the password relies on the running process ID, it changes on every execution instance.

### 2. Dynamic Analysis & Debugging

Because the generated password depends on the active Process ID (`_getpid()`), dynamic analysis was used to inspect the target's process state at runtime. The analysis environment was set up by launching a remote debugging session through Wine and attaching Ghidra's debugger using `gdbserver`.

#### Debugging Setup

1. **Host Server (Wine + GDB Server):**
   ```bash
   wine gdbserver.exe 127.0.0.1:12345 PIDXploit.exe

2. **Attach Ghidra:**
   we attach the remote to debugging session to ghidra by running the following command on the gdb terminal console:
   ```bash
   (gdb) target remote 127.0.0.1:12345

#### Execution Manipulation
The streategy is to get the PID before the program can execute any user/programmer written code.
The first breakpoint we set is at 0x401499 using the `break` command in gdb console:
```bash
      (gdb) break *0x401499
```

```x86asm   
        0040148b 55              PUSH       EBP
        0040148c 89 e5           MOV        EBP,ESP
        0040148e 83 e4 f0        AND        ESP,0xfffffff0
        00401491 83 ec 40        SUB        ESP,0x40
        00401494 e8 a7 05        CALL       ___main                                          undefined ___main(void)
                 00 00
        00401499 c7 04 24        MOV        dword ptr [ESP]=>local_50,s_Enter_the_password   = "Enter the password: "
                 71 50 40 00
        004014a0 e8 63 26        CALL       _printf                                          int _printf(char * _Format, ...)
                 00 00
```
Once the breakpoint is hit, at 0x401499, we can examine the contents of the registers. One register of interest is the **EIP** register since it points to the next instruction to be executed by the CPU. At this point, we change the EIP value to point to the location of the call to getpid; this is at 0x401466 using the `set` command:
```bash
   (gdb) set $eip = 0x401466
```

```x86asm 
                             _generate_password
                             ....
        00401463 83 ec 28        SUB        ESP,0x28
        00401466 e8 51 0c        CALL       _getpid                                          int _getpid(void)
                 00 00
        0040146b 89 45 f4        MOV        dword ptr [EBP + local_10],EAX
                           ....
```
Furthermore, we set a brekapoint at 0x40146b to ensure we can read the value before resuming program flow. 
```bash
   (gdb) break *0x40146b
```
Once the breakpoint at 0x40146b has been hit, we examine the contents of the register **EAX**, which contains the return value of the function call, using the `print` command in gdb
```bash
   (gdb) p/u $eax
```
The command above returns the unsigned decimal value of register EAX. This is the pid.

We then resume original program flow by setting the EIP to point to 0x401499, where we jumped from.
```bash
   (gdb) set $eip=0x401499
```
The original breakpoints will be hit again but just continue program execution and supply the valid password.

