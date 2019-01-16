# Homemade-Decompiler

*Authors: Jonathan Jacobi && Shahaf Cohen Tarica*

We wrote a decompiler in Python as our final project for our degree, and this is the result!

This is not perfect, we still have a ton to add ... don't expect it to be as good as IDA's HexRays :)

# Requirements

* This is aimed to be used on x86_64 ELF binaries.
* Python2.7 installed.
* [pwntools](https://github.com/Gallopsled/pwntools)

# Usage

`python2.7 <path_to_project>/src/decompiler.py <input_file> <target_function_name> [-o <output_file>]`

# TODOs

* Add better support for functions with return value.
* Add support for pointers / dereferences.
* Add variable declerations for local variables.
 
