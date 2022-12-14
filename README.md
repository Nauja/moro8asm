# moro8asm

[![CI](https://github.com/Nauja/moro8asm/actions/workflows/CI.yml/badge.svg)](https://github.com/Nauja/moro8asm/actions/workflows/CI.yml)
[![CI Docs](https://github.com/Nauja/moro8asm/actions/workflows/CI_docs.yml/badge.svg)](https://github.com/Nauja/moro8asm/actions/workflows/CI_docs.yml)
[![Documentation Status](https://readthedocs.org/projects/moro8asm/badge/?version=latest)](https://moro8asm.readthedocs.io/en/latest/?badge=latest)
[![GitHub license](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/Nauja/moro8asm/master/LICENSE)

Assembler for the [moro8](https://github.com/Nauja/moro8) fantasy CPU written in ANSI C.

## Why

While there already exist C compilers for 6502 based systems which can even target the NES such as [cc65](https://github.com/cc65/cc65), they are often more complex than needed for the sole purpose of compiling C code for the moro8 fantasy CPU where the limitations are clearly identified. Also, the moro8 fantasy CPU doesn't aim to strictly emulate the 6502 microprocessor or the NES. In fact, it greatly differs in terms of hardware and capabilities.

For those reasons, and also for educational purposes, I decided to write this assembler.

## Usage

todo

Check the [documentation](https://moro8asm.readthedocs.io/en/latest/) to find more examples and learn about the API.

## Build Manually

Copy the files [moro8asm.c](https://github.com/Nauja/moro8asm/blob/main/moro8asm.c) and [moro8asm.h](https://github.com/Nauja/moro8asm/blob/main/moro8asm.h) into an existing project.

Comment or uncomment the defines at the top of `moro8asm.h` depending on your configuration:

```c
/* Define to 1 if you have the <stdio.h> header file. */
#ifndef HAVE_STDIO_H
#define HAVE_STDIO_H 1
#endif

/* Define to 1 if you have the <stdlib.h> header file. */
#ifndef HAVE_STDLIB_H
#define HAVE_STDLIB_H 1
#endif

/* Define to 1 if you have the <string.h> header file. */
#ifndef HAVE_STRING_H
#define HAVE_STRING_H 1
#endif

...
```

You should now be able to compile this library correctly.

## Build with CMake

Tested with CMake >= 3.13.4:

```
git clone https://github.com/Nauja/moro8asm.git
cd moro8asm
git submodule init
git submodule update
mkdir build
cd build
cmake ..
```

CMake will correctly configure the defines at the top of [moro8asm.h](https://github.com/Nauja/moro8asm/blob/main/fs.h) for your system.

You can then build this library manually as described above, or by using:

```
make
```

This will generate `moro8asm.a` if building as a static library and `libmoro8asm.so` in the `build` directory.

You can change the build process with a list of different options that you can pass to CMake. Turn them on with `On` and off with `Off`:
TODO

## Build with Visual Studio

Generate the Visual Studio solution with:

```
mkdir build
cd build
cmake .. -G "Visual Studio 16 2019"
```

You can now open `build/moro8asm.sln` and compile the library.

## License

Licensed under the [MIT](https://github.com/Nauja/moro8asm/blob/main/LICENSE) License.
