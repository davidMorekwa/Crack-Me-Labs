# [ixp-s CrackMe-0x1] - CrackMe Writeup

**Difficulty:** Medium 
**Category:** Reverse Engineering  
**Platform:** Windows 
**Target Architecture:** x86  

## Executive Summary

The objective of the lab is to find the key.

---

## File Information

- **Filename:** CrackMe-0x1.exe
- **SHA-256:** `687f07edb1f349cac87a9fc2f297a962cd69767698eda18f65c4f239b786be33`
- **File Type:** `PE32 executable (console) Intel 80386, for MS Windows`

---

## Tools Used
- **OS:** Linux(REMnux)
- **Disassembler / Decompiler:** Ghidra 
- **Debugger:** Ghidra, gdbserver, gdb 

---

## Walkthrough

### 1. Initial Triage & Static Analysis
Initial triage revealed the program entry point at 0x4021db. The program import some dll files e.g. `api-ms-win-crt-runtime-l1-1-0.dll`, `api-ms-win-crt-stdio-l1-1-0.dll` etc which revealed that the program was compiled by Microsoft Visual Studio.

Some interesting string were found when I run the `strings` command. they included: Password, Wrong, Success, bad cat etc. I cross-referenced their use to get the user-written code. The main function is a `0x401280`.

At first glance, we see references to `std::cout` and `std::cin` types which are used to print to console and capture user input repsectively. 

```c
  print_to_console((basic_ostream<> *)cout_exref);
  read_input_from_console((basic_istream<> *)cin_exref,user_input);
```

I renamed the function at `0x401820` to `print_to_console` for my analysis. The function creates a streambuffer and writes the string 'Password' and prints it to the console

```c
...
  _Var7 = std::basic_streambuf<>::sputn(*(basic_streambuf<> **)(param_1 + *(int *)(iVar6 + 4) + 0x38),"Password:",(ulonglong)uVar3 << 0x20);
...
```
I also renamed the function at `0x401c50` to `read_input_from_console`. This function captures user input from the console and saves it to a local variable `user_input`

Some interest steps are taken by the program. A local variable `local_4c` is assigned the value of the captured console input i.e. user_input.

```c
...
local_4c = (byte ****)user_input;
...
```

The variable is then referenced in key areas within the program.
```c
    ...
    memcpy(pppppbVar7,local_4c,uVar5 + 1);
    ...
    if (0xf < local_70) {
    pppppbVar4 = (byte *****)local_4c;
    }
    ...
    the reassigned variable is used in a critical comparison operation loop
    ...
    while (uVar5 = uVar2 - 4, 3 < uVar2) {
      if (*pppppbVar6 != *pppppbVar4) goto LAB_00401436;
      pppppbVar6 = pppppbVar6 + 1;
      pppppbVar4 = pppppbVar4 + 1;
      uVar2 = uVar5;
    }
    ...
```

From the above, we now know the critical variable we need to extract is `pppppbVar6` which is compared to the captured console input. This is the key.

### 2. Dynamic Analysis

#### Debugging Setup

1. **Host Server (Wine + GDB Server):**
   ```bash
   wine gdbserver.exe 127.0.0.1:12345 PIDXploit.exe

2. **Attach Ghidra:**
   we attach the remote to debugging session to ghidra by running the following command on the gdb terminal console:
   ```bash
   (gdb) target remote 127.0.0.1:12345

#### Memory Analysis
Our first breakpoint is set at `0x4012e4`, right after the call to `read_input_from_console` function
```asm
...
        004012c4 c7 45 fc        MOV        dword ptr [EBP + local_8],0x0
                 00 00 00 00
        004012cb 8b 0d 74        MOV        ECX,dword ptr [->MSVCP140.DLL::std::cout]        = 00003d4c
                 30 40 00
        004012d1 e8 4a 05        CALL       print_to_console                                 basic_ostream<char,struct_std::c
                 00 00
        004012d6 8b 0d 68        MOV        ECX,dword ptr [->MSVCP140.DLL::std::cin]         = 00003dde
                 30 40 00
        004012dc 8d 55 c0        LEA        EDX=>user_input,[EBP + -0x40]
        004012df e8 6c 09        CALL       read_input_from_console                          basic_istream<char,struct_std::c
                 00 00
        004012e4 83 7d d4 10     CMP        dword ptr [EBP + local_30],0x10
```
I used `testpassword` as my dummy key. At `0x40130a`, the length of our dummy key is compared to `0x10`

```asm
        ...
        004012eb 8b 75 d0        MOV        ESI,dword ptr [EBP + local_34]
        ...
        0040130a 83 fe 10        CMP        ESI,0x10
        ...
```

```bash
    (gdb) p/x $esi

    output:
    $60 = 0xc
```

since our string length is less than 0x10, continuing program execution will lead to program termination without any string comparison. Thus we need to change the value of register ESI using the `set` command in gdb and validate using `print` command

```bash
    (gdb) set $esi = 0x11
    (gdb) p/x $esi
    output:
    $61 = 0x11
```

Our next breakpoint is at `ox401387`, right after the `memcpy` function call. Examining the memory address at register EAX after the function call, we note that our dummy string is stored at `0x412a68` memory address.
```bash
    (gdb) x/s 0x412a68
    output:
    0x412a68:       "testpassword"
```

The next interesting block of code is the loop at `0x4013a2`. After stepping the instruction execution within the loop, we discover that a local variable `local_18` is a signed the contents of register `AL` which contains ASCII strings.

```asm
...
                             LAB_004013a2                                    XREF[1]:     004013c9(j)  
        004013a2 b8 cd cc        MOV        EAX,0xcccccccd
                 cc cc
        004013a7 4e              DEC        ESI
        004013a8 f7 e1           MUL        ECX
        004013aa c1 ea 03        SHR        EDX,0x3
        004013ad 8a c2           MOV        AL,DL
        004013af c0 e0 02        SHL        AL,0x2
        004013b2 8d 0c 10        LEA        ECX,[EAX + EDX*0x1]
        004013b5 8b 45 b8        MOV        EAX,dword ptr [EBP + local_4c]
        004013b8 02 c9           ADD        CL,CL
        004013ba 2a c1           SUB        AL,CL
        004013bc 8b ca           MOV        ECX,EDX
        004013be 04 30           ADD        AL,0x30
        004013c0 88 06           MOV        byte ptr [ESI]=>local_18,AL
        004013c2 8b c2           MOV        EAX,EDX
        004013c4 89 45 b8        MOV        dword ptr [EBP + local_4c],EAX
        004013c7 85 c0           TEST       EAX,EAX
        004013c9 75 d7           JNZ        LAB_004013a2
...
```
Thus, we set our next breakpoint at `0x4013cb` and examine the contents of `local_18` variable in memory. The address is stored in register ESI

```bash
    (gdb) x/s $esi
    output:
    0x32fed1:       "****"
```
I came to find out that the value stored here is the answer. however we need to validate that its the string being compared to our dummy key. 

At `0x401415` another string length comparison is made, but this time its against the correct key length.
```asm
...
        00401415 3b 75 90        CMP        ESI,dword ptr [EBP + local_74]
...
```
```bash
    (gdb) p/x $esi
    output:
    $73 = 0xc

    (gdb) x/xb $ebp-0x70
    output:
    0x32fe78:       0x04
```
Since we already know our dummy string is 12 characters long, the validation check will fail thus we need to change the value of register ESI
```bash
    (gdb) set $esi = 0x04
```
At `0x40141d` we need to validate that *Carry Flag* is not set, and change if need be.

The CMP instruction at `0x401422` compares the values of pointers stored in register ECX and EDX.

```asm
...
                             LAB_00401420                                    XREF[1]:     0040142f(j)  
        00401420 8b 02           MOV        EAX,dword ptr [EDX]
        00401422 3b 01           CMP        EAX,dword ptr [ECX]
...
```
Examining the values in memory:
```bash
    (gdb) x/s $edx
    output: 
    0x412a68:       "testpassword"

    (gdb) x/s $ecx
    output:
    0x32fe68:       "****"
```

Running the program again and supplying the correct key prints the message `Success!`

```bash
remnux@remnux:~/Labs/Crack-Me/ixp-s$ wine CrackMe-0x1.exe 
Password:****
Success!remnux@remnux:~/Labs/Crack-Me/ixp-s$ 
```
