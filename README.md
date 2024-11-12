# SysWhispers3

SysWhispers helps with evasion by generating header/ASM files implants can use to make direct system calls.

## Official Discord Channel

Come hang out on Discord!

[![Inceptor Server](https://discordapp.com/api/guilds/1155753953108164628/widget.png?style=banner3)](https://discord.gg/f6w6dwZq)

### Why on earth didn't I create a PR to SysWhispers2?

The reason for SysWhispers3 to be a standalone version are many, but the most important are:

* SysWhispers3 is the de-facto "fork" used by [Inceptor][1], and implements some utils class which are not relevant to the 
  original version of the tool.
* SysWhispers2 is moving towards supporting NASM compilation (for gcc/mingw), while this version is specifically designed and 
  tested to support MSVC (because [Inceptor][1] will stay a Windows-only framework for the near future).
* SysWhispers3 contains partially implemented features (such as egg-hunting) which would not be sensible to include
  in the original version of the tool.

## Differences with SysWhispers2

The usage is pretty similar to [SysWhispers2](https://github.com/jthuraisamy/SysWhispers2), with the following exceptions:

* It also supports x86/WoW64
* It supports syscalls instruction replacement with an EGG (to be dynamically replaced)
* It supports direct jumps to syscalls in x86/x64 mode (in WOW64 it's almost standard)
* It supports direct jumps to random syscalls (borrowing [@ElephantSeal's idea](https://twitter.com/ElephantSe4l/status/1488464546746540042))

A better explanation of these features are better outlined i the blog post [SysWhispers is dead, long live SysWhispers!][2]

## Introduction

Security products, such as AVs and EDRs, usually place hooks in user-mode API functions to analyse a program execution 
flow, in order to detect potentially malicious activities.

SysWhispers2 is a tool designed to generate header/ASM pairs for any system call in the core kernel image 
(`ntoskrnl.exe`), which can then be integrated and called directly from C/C++ code, evading user-lands hooks. 

The tool, however, generates some patters which can be included in signatures, or behaviour which can be detected 
at runtime.

SysWhispers3 is built on top of SysWhispers2, and integrates some helpful features to bypass these forms of detection.

## Installation

```
C:\> git clone https://github.com/klezVirus/SysWhispers3.git
C:\> cd SysWhispers3
C:\> python .\syswhispers.py --help
```

## Usage and Examples

The help shows all the available commands and features of the tool:

```
C:\>python syswhispers.py -h

usage: syswhispers.py [-h] [-p PRESET] [-a {x86,x64}] [-m {embedded,egg_hunter,jumper,jumper_randomized,vectored}] [-f FUNCTIONS] -o OUT_FILE [--int2eh] [--wow64] [-v] [-d]

SysWhispers3 - SysWhispers on steroids

optional arguments:
  -h, --help            show this help message and exit
  -p PRESET, --preset PRESET
                        Preset ("all", "common")
  -a {x86,x64}, --arch {x86,x64}
                        Architecture
  -c {msvc,mingw,all}, --compiler {msvc,mingw,all}
                        Compiler
  -m {embedded,egg_hunter,jumper,jumper_randomized,vectored}, --method {embedded,egg_hunter,jumper,jumper_randomized,vectored}
                        Syscall recovery method
  -f FUNCTIONS, --functions FUNCTIONS
                        Comma-separated functions
  -o OUT_FILE, --out-file OUT_FILE
                        Output basename (w/o extension)
  --int2eh              Use the old `int 2eh` instruction in place of `syscall`
  --wow64               Use Wow64 to run x86 on x64 (only usable with x86 architecture)
  -v, --verbose         Enable debug output
  -d, --debug           Enable syscall debug (insert software breakpoint)
```

### Command Lines

#### Standard SysWhispers, embedded system calls (x64)

```powershell
# Export all functions with compatibility for all supported Windows versions (see example-output/).
py .\syswhispers.py --preset all -o syscalls_all

# Export just the common functions (see below for list).
py .\syswhispers.py --preset common -o syscalls_common

# Export NtProtectVirtualMemory and NtWriteVirtualMemory with compatibility for all versions.
py .\syswhispers.py --functions NtProtectVirtualMemory,NtWriteVirtualMemory -o syscalls_mem
```

#### SysWhispers3-only samples 

```powershell
# Normal SysWhispers, 32-bits mode
py .\syswhispers.py --preset all -o syscalls_all -m jumper --arch x86

# Normal SysWhispers, using WOW64 in 32-bits mode (only specific functions)
py .\syswhispers.py --functions NtProtectVirtualMemory,NtWriteVirtualMemory -o syscalls_mem --arch x86 --wow64

# Egg-Hunting SysWhispers, to bypass the "mark of the sycall" (common function)
py .\syswhispers.py --preset common -o syscalls_common -m egg_hunter

# Jumping/Jumping Randomized SysWhispers, to bypass dynamic RIP validation (all functions) using MinGW as the compiler
py .\syswhispers.py --preset all -o syscalls_all -m jumper -c mingw


```

### Script Output

```
PS C:\Projects\SysWhispers2> py .\syswhispers.py --preset common --out-file temp\syscalls_common -v 
                                                       
                  .                         ,--.
,-. . . ,-. . , , |-. o ,-. ,-. ,-. ,-. ,-.  __/
`-. | | `-. |/|/  | | | `-. | | |-' |   `-. .  \
`-' `-| `-' ' '   ' ' ' `-' |-' `-' '   `-'  '''
     /|                     |  @Jackson_T
    `-'                     '  @modexpblog, 2021

                      Edits by @klezVirus,  2022
SysWhispers3: Why call the kernel when you can whisper?


Common functions selected.

Complete! Files written to:
        temp\syscalls_common.h
        temp\syscalls_common.c
        temp\syscalls_common_.asm
Press a key to continue...

```

## Importing into Visual Studio

1. Copy the generated H/C/ASM files into the project folder.
2. In Visual Studio, go to *Project* → *Build Customizations...* and enable MASM.
3. In the *Solution Explorer*, add the .h and .c/.asm files to the project as header and source files, respectively.
4. Go to the properties of the ASM file, and set the *Item Type* to *Microsoft Macro Assembler*.

## Compiling outside of Visual Studio

### Windows

Makefile for 64 bits:

`Makefile.msvc`
```
OPTIONS = -Zp8 -c -nologo -Gy -Os -O1 -GR- -EHa -Oi -GS-
LIBS = libvcruntime.lib libcmt.lib ucrt.lib kernel32.lib

program:
  ML64 /c syscalls-asm.x64.asm /link /NODEFAULTLIB /RELEASE /MACHINE:X64
  cl.exe $(OPTIONS) syscalls.c  program.c
  link.exe /OUT:program.x64.exe -nologo $(LIBS) /MACHINE:X64 -subsystem:console -nodefaultlib syscalls-asm.x64.obj syscalls.obj program.obj
```

Makefile for 32 bits:

`Makefile.msvc`
```
OPTIONS = -Zp8 -c -nologo -Gy -Os -O1 -GR- -EHa -Oi -GS-
LIBS = libvcruntime.lib libcmt.lib ucrt.lib kernel32.lib

program:
  ML /c syscalls-asm.x86.asm /link /NODEFAULTLIB /RELEASE /MACHINE:X86
  cl.exe $(OPTIONS) syscalls.c  program.c
  link.exe /OUT:program.x86.exe -nologo $(LIBS) /MACHINE:X86 -subsystem:console -nodefaultlib syscalls-asm.x86.obj syscalls.obj program.obj
```

Compile with nmake:
```
nmake -f Makefile.msvc
```

### Linux

Makefile for both 64 and 32 bits:

`Makefile.mingw`
```
CC_x64 := x86_64-w64-mingw32-gcc
CC_x86 := i686-w64-mingw32-gcc
OPTIONS := -masm=intel -Wall

program:
  $(CC_x64) syscalls.c program.c -o program.x64.exe $(OPTIONS)
  $(CC_x86) syscalls.c program.c -o program.x86.exe $(OPTIONS)
```

Compile with make:
```
make -f Makefile.mingw
```

## Caveats and Limitations

- The Egg-Hunter functionality is not implemented within this tool, it is in [Inceptor][1].
- System calls from the graphical subsystem (`win32k.sys`) are not supported.
- Tested on Visual Studio 2019/2022 with Windows 10 SDK. 
- Support for NASM is not guaranteed.
- Support for GCC and MinGW is not guaranteed.

## Troubleshooting

#### From SysWhispers2
- Type redefinitions errors: a project may not compile if typedefs in `syscalls.h` have already been defined.
  - Ensure that only required functions are included (i.e. `--preset all` is rarely necessary).
  - If a typedef is already defined in another used header, then it could be removed from `syscalls.h`.

#### New
- With `--verbose`, it is possible to enable troubleshooting output during code generation.
- With `--debug`, the tool will insert a software breakpoint in the syscall stub, to ease the debugging in WinDbg.
- If you get a `error A2084:constant value too large` during compilation, regenerates the stubs.

## Credits

#### SysWhispers2

Developed by [@Jackson_T](https://twitter.com/Jackson_T) and [@modexpblog](https://twitter.com/modexpblog), 
but builds upon the work of many others:

- [@FoxHex0ne](https://twitter.com/FoxHex0ne) for cataloguing many function prototypes and typedefs in a machine-readable format.
- [@PetrBenes](https://twitter.com/PetrBenes), [NTInternals.net team](https://undocumented.ntinternals.net/), and [MSDN](https://docs.microsoft.com/en-us/windows/) for additional prototypes and typedefs.
- [@Cn33liz](https://twitter.com/Cneelis) for the initial [Dumpert](https://github.com/outflanknl/Dumpert) POC implementation.

#### SysWhispers2 (x86/WOW64)

- [@rooster](https://github.com/mai1zhi2) for creating a sample x86/WOW64 compatible fork.

#### Others

- [@ElephantSe4l](https://mobile.twitter.com/elephantse4l) for the idea about randomizing the jumps to the syscalls.
- [@S4ntiagoP](https://twitter.com/s4ntiago_p) for the incredible work on [nanodump](https://github.com/helpsystems/nanodump), which gave me tons of ideas.

## Licence

As the original, this project is also licensed under the Apache License 2.0.


[1]: https://github.com/klezVirus/inceptor
[2]: https://klezvirus.github.io/RedTeaming/AV_Evasion/NoSysWhisper/
