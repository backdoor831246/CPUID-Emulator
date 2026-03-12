# CPUID-Emulator
[Telegram Channel](https://t.me/+5EHmo7zE-KBlYzMy)
Simple Windows DLL that intercepts and emulates the `CPUID` instruction inside the current process.

## Overview

This project hooks `CPUID` instructions by replacing them with an invalid instruction (`UD2`).
When the instruction is executed, a vectored exception handler catches the exception and returns custom CPU information.

This allows spoofing CPU vendor, features, and brand string.

## Features

* Hooks all `CPUID` instructions in the main module
* Uses **Vectored Exception Handler (VEH)**
* Emulates several CPUID leaves
* Customizable CPU vendor and brand string
* Works completely in usermode

## Example Spoofed CPU

```
Intel(R) Core(TM) i9-13900K CPU @ 3.00GHz
```

## How it works

1. Scan the `.text` section of the main module.
2. Find `CPUID` instructions (`0F A2`).
3. Replace them with `UD2` (`0F 0B`).
4. When executed, a VEH handler emulates CPUID results.

