# [lvl0EasyCrackMes] - CrackMe Writeup

**Difficulty:** Easy
**Category:** Reverse Engineering  
**Platform:** Windows 
**Target Architecture:** x86  

## Executive Summary

The objective of the lab is to find the 'programmer's' secret.

---

## File Information

- **Filename:** lvl0.exe
- **SHA-256:** `5280c41473a9e3ca2fd02cb1ace8c07a696aa6acb6ce45b09845a2a773c48356`
- **File Type:** `PE32 executable (console) Intel 80386, for MS Windows`

---

## Tools Used
- **OS:** Linux(REMnux)
- **Disassembler / Decompiler:** Ghidra 

---

## Walkthrough
### Initial Triage and Static Analysis
This was an easy lab since the possible values are hardcoded into the program. One of them is the correct one.

```c
    std::allocator<char>::allocator();
    std::string::string(local_48,"C++ is best",&local_17);
    std::allocator<char>::~allocator((allocator<char> *)&local_17);
    std::allocator<char>::allocator();
    std::string::string(local_60,"Dota 2 >>>>> LoL",&local_16);
    std::allocator<char>::~allocator((allocator<char> *)&local_16);
    std::allocator<char>::allocator();
    std::string::string(local_78,"Python is trash",&local_15);
    std::allocator<char>::~allocator((allocator<char> *)&local_15);
    std::allocator<char>::allocator();
    std::string::string(local_90,"Hate from africa",&local_14);
    std::allocator<char>::~allocator((allocator<char> *)&local_14);
    std::allocator<char>::allocator();
    std::string::string(local_a8,&DAT_004060a3,&local_13);
    std::allocator<char>::~allocator((allocator<char> *)&local_13);
    std::allocator<char>::allocator();
    std::string::string(local_c0,"fentanyl",&local_12);
    std::allocator<char>::~allocator((allocator<char> *)&local_12);
    std::allocator<char>::allocator();
    std::string::string(local_d8,"imgay",&local_11);
    std::allocator<char>::~allocator((allocator<char> *)&local_11)
```