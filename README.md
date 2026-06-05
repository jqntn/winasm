# winasm

Ultra-minimal x64 Windows **Hello, World!** — hand-written assembly that NASM turns straight into a runnable `.exe`, no linker required.

## Build

```powershell
nasm -f bin -o hello.exe hello.asm
```

## Run

```powershell
.\hello.exe
# Hello, World!
```
