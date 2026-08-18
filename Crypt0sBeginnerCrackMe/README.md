# [Crypt0s] - CrackMe Writeup

**Difficulty:** Easy
**Category:** Reverse Engineering  
**Platform:** Windows 
**Target Architecture:** x86  

## Executive Summary

The objective of the lab is to find the username and password.

---

## File Information

- **Filename:** cryto.exe
- **SHA-256:** `70b46a0e2eb237f533cec8e9854960498d64275a944be67cc0f964092eae43a7`
- **File Type:** `PE32 executable (console) Intel 80386, for MS Windows`

---

## Tools Used
- **OS:** Linux(REMnux)
- **Disassembler / Decompiler:** Ghidra 

---

## Walkthrough
### Initial Triage and Static Analysis
This was an easy lab since the credentials were hardcoded into the program. Therefore, once the program was opened on ghidra, the Username and Password were right there. Lol.

```c
    local_14 = DAT_00426008 ^ (uint)&stack0xfffffffc;
    ExceptionList = &local_10;
    @__CheckForDebuggerJustMyCode@4(&DAT_00429033);
    thunk_FUN_00415890("****");
    local_8 = 0;
    thunk_FUN_00415890("******");
    local_8._0_1_ = 1;
    thunk_FUN_00415a10();
    local_8._0_1_ = 2;
```