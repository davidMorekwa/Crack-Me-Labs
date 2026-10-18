# 'My Third Crackme' Walkthrough

## Executive Summary
- This binary is a 64-bit Windows reverse engineering challenge (crackme). It prompts the user for a 17-character password, validates the input through an internal state machine combined with an anti-debugging check, and decrypts an internal flag using XOR operations upon successful validation.

## File Information
- **FileName:** *My_third_Crackme.exe*
- **File Type:** PE64 executable for MS Windows (console), AMD x86-64, 6 sections (`.text`, `.rdata`, `.data`, `.pdata`, `.tls`, `.reloc`)

## Tools used
- **OS:** Linux
- **Dissasembler:** Ghidra
- **Script:** Python

# Walkthrough
## Static Analysis
### Import/Exports
- Key libraries imported by the sample include: `kernel32.dll` and Microsoft Universal C Runtime (`ucrtbase.dll` / MSVC CRT).
  - **`kernel32.dll`**: Imports of interest include `IsDebuggerPresent`, which is actively utilized as an anti-analysis mechanism, as well as memory and execution controls (`Sleep`, `VirtualProtect`, `SetUnhandledExceptionFilter`).
  - **CRT / Standard Library**: Standard I/O, memory, and string manipulation functions such as `fgets`, `puts`, `setvbuf`, `fflush`, `strlen`, `strcspn`, `memcpy`, and `malloc`.

---

### Disassembly and Decompilation
- The program's initial execution passes through the CRT startup wrapper (`__scrt_common_main_seh`) at `0x140001020`, which sets up runtime structures before invoking the primary logic in `FUN_main` at `0x140001440`.

```C
uVar9 = FUN_main((ulonglong)DAT_140005058, DAT_140005060, DAT_140005068, param_4);
```

- `FUN_main` contains the full verification and flag routine.

---

#### FUN_main: Password Input & Length Validation
- The binary requests input by prompting `"enter the password : "` and reads up to `0x40` (64) bytes via `fgets` into a local stack buffer (`input_buff` at `[RBP - 0x60]`).
- It strips trailing carriage return and newline characters (`\r`, `\n`) using `strcspn`.
- The string length is checked against `0x11` (17 decimal). If the length does not match 17 characters, it immediately branches to print `"Not today..."`.

```C
  sVar4 = strcspn((char *)input_buff, "\r\n");
  input_buff[sVar4] = 0;
  sVar4 = strlen((char *)input_buff);
  if (sVar4 == 0x11) {
    ...
  }
  puts("Not today...");
```

```ASM
1400014aa: CALL 0x140002800            ; strcspn(input, "\r\n")
1400014af: MOV  byte ptr [RBP + RAX*0x1 + -0x60], 0x0
1400014b7: CALL 0x140002810            ; strlen(input)
1400014bc: CMP  RAX, 0x11              ; Compare length with 17
1400014c0: JNZ  0x14000162d            ; Branch to "Not today..." if != 17
```

---

#### Anti-Debugging Detection (`IsDebuggerPresent`)
- Inside `FUN_main`, the program invokes `IsDebuggerPresent()` at `0x1400014c8`.
- The boolean return value (`BVar1`, where `1` indicates a debugger is attached and `0` indicates normal execution) is directly factored into the expected end state calculation:

```C
BVar1 = IsDebuggerPresent();
...
if ((byte)((BVar1 == 0) + 0x10U) == (&DAT_1400030e0)[uVar7 + (ulonglong)bVar5 * 0x10])
```

- When running without a debugger (`BVar1 == 0`), the expected final state is `1 + 0x10 = 0x11` (17). If a debugger is present (`BVar1 == 1`), the expected state becomes `0 + 0x10 = 0x10` (16), causing validation to fail.

---

#### Password Transformation & State Machine Validation
- The binary iterates over the 17 input characters in 2-character steps.
- Each character is transformed via an XOR with `10` (`0x0A`), incremented by 1, and masked to a 4-bit nibble (`& 0x0F`):

```C
while( true ) {
  uVar7 = (ulonglong)((byte)((input_buff[lVar6] ^ 10) + 1) & 0xf);
  if (lVar6 == 0x10) break;
  bVar5 = (&DAT_1400030e0)
          [(ulonglong)((byte)((input_buff[lVar6 + 1] ^ 10) + 1) & 0xf) +
           (ulonglong)(byte)(&DAT_1400030e0)[uVar7 + (ulonglong)bVar5 * 0x10] * 0x10];
  lVar6 = lVar6 + 2;
}
```

```ASM
1400014e0: MOVZX R8D, byte ptr [RBP + RSI*0x1 + -0x60]
1400014e6: XOR   R8B, 0xa              ; XOR with 10
1400014ea: INC   R8B                   ; + 1
1400014ed: MOVZX R8D, R8B
1400014f1: AND   R8D, 0xf              ; & 0x0F
```

- `DAT_1400030e0` acts as a 2D transition matrix indexed by the current state and transformed input values.
- The 17th character (`lVar6 == 0x10`) computes the final state index:
  ```C
  (&DAT_1400030e0)[uVar7 + (ulonglong)bVar5 * 0x10]
  ```
  which must evaluate to `0x11` to pass.

---

#### Flag Decryption (`XOR 0x77`)
- Once the state verification check succeeds, the program executes a decryption loop that reconstructs the flag string into a local stack buffer (`[RBP - 0x20]`).
- A 17-byte ciphertext array located at `DAT_1400030b0` through `DAT_1400030c0` is decrypted using a static single-byte XOR key: **`0x77`** (`119` / ASCII `'w'`).

```ASM
14000153f: MOVZX EAX, byte ptr [0x1400030b0] ; Load ciphertext byte (0x3B)
140001546: XOR   AL, 0x77                    ; Decrypt: 0x3B ^ 0x77 = 0x4C 
140001548: MOV   byte ptr [RBP + -0x20], AL  ; Store in stack buffer
14000154b: MOVZX EAX, byte ptr [0x1400030b1] ; Load ciphertext byte (0x12)
140001552: XOR   AL, 0x77                    ; Decrypt: 0x12 ^ 0x77 = 0x65
140001554: MOV   byte ptr [RBP + -0x1f], AL  ; Store in stack buffer
...
1400015ff: MOVZX EAX, byte ptr [0x1400030c0] ; Load ciphertext byte (0x13)
140001606: XOR   AL, 0x77                    ; Decrypt: 0x13 ^ 0x77 = 0x64
140001608: MOV   byte ptr [RBP + -0x10], AL  ; Store in stack buffer
14000160b: MOV   byte ptr [RBP + -0xf], 0x0  ; Null-terminate string
```

- Finally, the program prints the success message and flag:

```C
puts("Yeaaaaa!!! Discord : imrate");
printf("Flag : CMO{%s}\n", &local_38);
```

- Output:
  ```
  Yeaaaaa!!! Discord : imrate
  Flag : CMO{*********}
  ```

## Dynamic Analysis
### Setup
1. Create Remote Debugging session
```bash
  winedbg --gdb --no-start --port 12345 My_third_Crackme.exe
```
2. Attach python script
```bash
  gdb -x script.py
```

### Script
The GDB Python script handles two main verification checkpoints during runtime.
  - **Length Requirement** `Breakpoint5`: Triggers after the input length check and forces $rax = 0x11 (17), allowing any entered string to pass the length constraint
  - **Anti-Debugging Check** `Breakpoint2`: Intercepts the return of IsDebuggerPresent and overrides $rax = 0x0, ensuring the program calculates the expected state based on an unattached environment
  - **State Verification** `Breakpoint3`: Intercepts the condition comparison at 0x140001539 and sets the Zero Flag ($eflags |= 0x40), allowing execution to flow into the flag decryption and printing block.

Once execution completes, the decrypted flag is printed directly to the console window.
