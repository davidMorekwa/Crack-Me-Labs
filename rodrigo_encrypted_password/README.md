# [Rodrigo - Encrypted Password] - CrackMe Writeup

**Difficulty:** Medium
**Category:** Reverse Engineering  
**Platform:** Windows 
**Target Architecture:** x86  

## Executive Summary

The objective of the lab is to find the enxrypted password in the code.

---

## File Information
1. Exe file
- **Filename:** rodrigo_encrypted_password.exe
- **SHA-256:** `9dd33eeb833d6936f2c969ec6428245a67b09057afffdeee90c48fe813570087`
- **File Type:** `PE32 executable (console) Intel 80386, for MS Windows`
2. DLL file
- **Filename:** libmingwex-0.dll
- **SHA-256:** `b94b360fe491590108c784ae15db16c2dd2468400915cb81283e5c8f4428333f`
- **File Type:** `PE32 executable (DLL) (console) Intel 80386 (stripped to external PDB), for MS Windows`

---

## Tools Used
- **OS:** Linux(REMnux)
- **Disassembler / Decompiler:** Ghidra 
- **Debugger:** Ghidra, gdbserver, gdb 

---

## Walkthrough
### Initial Triage and Static Analysis 
The initial analysis suggests that the program evaluates the password on a character-by-character basis instead of relying on standard library functions e.g. `strcmp`.

The program loads a string onto memory and prints it.
```c
    ...
  local_89[0] = 0x45;
  local_89[1] = 0x96;
  local_89[2] = 0xcc;
  local_89[3] = 0x31;
  uVar1 = local_89._0_4_;
  local_89[0] = 0x45;
  local_89[4] = 0x8a;
  local_89[5] = 0x60;
  local_89[6] = 0xf4;
  local_89[7] = 200;
  local_89[8] = 0x9d;
  local_89[9] = 0xa0;
  local_89[10] = 0x70;
  local_89[0xb] = 0xf1;
  bVar5 = 0x96;
  local_89[0xc] = 0x53;
  local_89[0xd] = 1;
  local_89[0xe] = 0xed;
  local_89[0xf] = 0xc9;
  local_89[0x10] = 0xae;
  local_89[0x11] = 0xc;
  local_89[0x12] = 0xb2;
  local_89[0x13] = 0x60;
  local_89[0x14] = 0;
  pbVar6 = local_89;
  ...
  _printf((char *)local_89);
  ...
```
Afterwards, the user input is written at stack address `local_89+0x15`; right next to the previous string.
```c
    _scanf("%99s",local_89 + 0x15);
```
The user's input is then compared to a string stored in stack address `local_a7` on a character-by-character basis.
```c
...
    if (local_89[0x15] == 0x50) {
        if (true) {
        iVar4 = 0;
        do {
            local_a7[0] = local_a7[iVar4 + 1];
            local_89[0x15] = (local_89 + 0x15)[iVar4 + 1];
            if (local_a7[0] != local_89[0x15]) goto print_wrong_password;
            iVar4 = iVar4 + 1;
        } while (local_a7[0] != 0);
        }
    }
  ...
```
Thus to get the correct password, we need to examine the strings stored in the stack memory

### 2. Dynamic Analysis

#### Debugging Setup

1. **Host Server (Wine + GDB Server):**
   ```bash
   wine gdbserver.exe 127.0.0.1:12345 rodrigo_encrypted_password.exe

2. **Attach Ghidra:**
   we attach the remote to debugging session to ghidra by running the following command on the gdb terminal console:
   ```bash
   (gdb) target remote 127.0.0.1:12345

#### Memory Analysis
The first breakpoint we set is at 0x4021fc, which contains the instruction below.
```x86asm
...
        004021f4 c7 44 24        MOV        dword ptr [ESP + local_89],0x31cc9645
                 37 45 96 
                 cc 31
        004021fc 0f b6 44        MOVZX      EAX,byte ptr [ESP + local_89]
                 24 37
...
```
After the instruction at `0x4021f4` is executed the data is stored in the stack memory.
##### Key consideration
Ghidra has labled the local variables with -ve offsets e.g. -0x89. This is from a static POV without the running the program. At runtime, function prologues can push data onto stack which in turn affects the offsets of the local variable, thus we consider them when accessing the local varibles.

To get values/registers pushed onto stack during function prologue, we use the `frame` gdb command
```bash
    (gdb) info frame

    output:
        ...
    Saved registers:
    ebx at 0x60fedc, ebp at 0x60fee8, esi at 0x60fee0, edi at 0x60fee4, eip at 0x60feec
```
From the above we note that registers EBX, ESI, EDI have been pushed onto the stack. Since each register is 4-bytes, the offsets are affected by 12-bytes i.e. 0xC.

Thus to get the memory address where the data was written to we use:
```bash
    (gdb) x/4xw $ebp-0x89-0xC

    output:
    0x60fe53:       0x00000000      0x31cc9645      0x00000000      0x00000000
```

The next breakpoint set is at `0x402231` after the data has been written to memory.
```bash
    (gdb) x/8xw $ebp-0x89-0xC

    output:
    0x60fe53:       0x00000000      0x31cc9645      0xc8f4608a      0xf170a09d
    0x60fe63:       0xc9ed0153      0x60b20cae      0x00000000      0x00000000
```
#### Decryption of user prompt message
Trying to convert the hex values to string yields a wierd string which leads us to conclude that the string is encrypted.

This is the loop that decryptes the string:
```x86asm
                             LAB_00402231                                    XREF[1]:     00402242(j)  
        00402231 83 c8 01        OR         EAX,0x1
        00402234 83 c2 01        ADD        EDX,0x1
        00402237 0f af c1        IMUL       EAX,ECX
        0040223a 88 02           MOV        byte ptr [EDX]=>local_89+0x1,AL
        0040223c 0f b6 4a 01     MOVZX      ECX,byte ptr [EDX + local_89+0x2]
        00402240 84 c9           TEST       CL,CL
        00402242 75 ed           JNZ        LAB_00402231
```
Next, we set our breapoint at `0x402244`, immediately after the decrypting loop.
After each loop, the values in the memory address `0x60fe53` change to values that can be converted to string.

```bash
    (gdb) x/s $ebp-0x89-0xC+0x4

    output:
    0x60fe57:       "Enter the password: "
```
we add 4 bytes to the memory address `0x60fe53` because the first 4-bytes are null. The decryption yields a sensible string.

#### Decryption of encryptes password
From the decompiled psudocode, we see a local variable `local_a7` being populated with data. We set our breakpoint at `0x402288` then examine the memory address associated with the local_a7 variable
```x86asm
        00402260 c7 44 24        MOV        dword ptr [ESP + local_a7],0x1531150
                 19 50 11 
                 53 01
        00402268 0f b6 44        MOVZX      EAX,byte ptr [ESP + local_a7]
                 24 19
        0040226d ba 2c f0        MOV        EDX,0xfffff02c
                 ff ff
        00402272 66 89 54        MOV        word ptr [ESP + local_9f],DX
                 24 21
        00402277 8d 54 24 19     LEA        EDX=>local_a7,[ESP + 0x19]
        0040227b c7 44 24        MOV        dword ptr [ESP + local_a3],0xcaec9ed
                 1d ed c9 
                 ae 0c
        00402283 c6 44 24        MOV        byte ptr [ESP + local_9d],0x0
                 23 00

```
```bash
    (gdb) x/4xw $ebp-0xA7-0xC

    output:
    0x60fe35:       0x00000000      0x01531150      0x0caec9ed      0x0000f02c
```
from the output we see data has been written to memory

A loop is also available here to decrept the data written the the `0x60fe35` address space. 
```x86asm
                             LAB_00402290                                    XREF[1]:     004022a1(j)  
        00402290 83 c8 01        OR         EAX,0x1
        00402293 83 c2 01        ADD        EDX,0x1
        00402296 0f af c1        IMUL       EAX,ECX
        00402299 88 02           MOV        byte ptr [EDX]=>local_a7+0x1,AL
        0040229b 0f b6 4a 01     MOVZX      ECX,byte ptr [EDX + local_a7+0x2]
        0040229f 84 c9           TEST       CL,CL
        004022a1 75 ed           JNZ        LAB_00402290
```
we set a breakpoint at `0x4022a3` and examine the same memory address for the decrypted string.
```bash
    (gdb) x/s $ebp-0xA7-0xC+0x4

    output:
    0x60fe39:       "*****"
```
the string at this address is the decrypted password
