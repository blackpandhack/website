---
layout: post
title: "The first crackme of the NDK 2016"
description: "Solved with angr and radare2"
tags: [reverse, radare2, angr]
---

This crackme was the first of the series at the NDH 2016.

### Identifing the binary

To know what we have here, a **file** command can do the job. 

```
file ./lol_so_obfuscated
./lol_so_obfuscated: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, not stripped
```

As we can see here, this file is a x64 linux executable, not stripped. Nothing fancy.

### Play around with the binary
```
./lol_so_obfuscated
Usage ./lol_so_obfuscated <flag>

./lol_so_obfuscated  a
13
You're wrong.

./lol_so_obfuscated  aa
13 27
You're wrong.

./lol_so_obfuscated  aaaaaaaaa
13 27 9 3 6 15 9 3 8
You're wrong.
```

This binary take an input,
we can assume that it's print the encrypted input
and then print if it's a good input or not.

### Inspect the binary with radare2

{% img '2016-10-15-lol_so_obfuscated/main.png' %}

In the main function we can see the in left branch that the program cal encrypt() with str.lwskdhgkjsqnvkjwxchzeUBVWCXKJBNVWXCKJBGGG and the input
and then compare it to a unknow string

### Try to resolve the function with angr

```python
import angr, claripy

start = 0x400600       # The start of the main function
end = 0x400745         # The "You're right." block
bad_pass = 0x00400751  # The "You're wrong." block
bad_input = 0x004006f5 # The "Usage ./lol_so_obfuscated <flag>" block

proj = angr.Project('./lol_so_obfuscated', load_options={'auto_load_libs':False}) # Load the binary

argv1 = angr.claripy.BVS("argv1", 41 * 8) # Create the input, with the size of lwskdhgkjsqnvkjwxchzeUBVWCXKJBNVWXCKJBGGG, 41 bytes
state = proj.factory.entry_state(args=["./lol_so_obfuscated", argv1]) # Assign the input to the binary

path = proj.factory.path(state=state) # Create the path to the main function
ex = proj.surveyors.Explorer(start=path, find=(end), avoid=(bad_input, bad_pass)) # Specify the block to find and avoid
ex.run() # Explore the possibilities

if ex.found: # If we found one
    found = ex.found[0].state # Get the path found
    res = found.se.any_str(argv1) # Get the input of this path
    print(res) # print it
```

With this script, we can get the correct input in ~1min (ndh2k16_19ac2d414c11f6f9da5a1d3342e304bc)
