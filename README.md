# Homemade-Decompiler

*Authors: Jonathan Jacobi && Shahaf Cohen Tarica*

We wrote a decompiler in Python as our final project for our degree, and this is the result!

This is not perfect, there is still a **long** way until this becomes anywhere near HexRays' decompiler level ...
yet we're pretty happy with what we made :)

# Requirements

* This is aimed to be used on x86_64 ELF binaries.
* Python2.7 installed.
* [pwntools](https://github.com/Gallopsled/pwntools)

# Usage

`python2.7 ./src/decompiler.py [-h] [--output OUTPUT] input_file input_function`

# TODOs

* Add better support for functions with return value.
* Add support for pointers / dereferences.
* Add variable declerations for local variables.
* More... :)
 
