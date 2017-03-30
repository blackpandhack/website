---
layout: post
title: "Solving CMU binary bomb with angr"
author: "Noname"
description: "The 5 first phase of CMU binary bomb with radare2 and angr"
tags: [reverse, radare2, angr]
---

This crackme has six stages.
Each one represent a phase of the bomb to defuse.

### Identifing the binary

To know what we have here, a **file** command can do the job. 

```
file ./bomb
./bomb: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, not stripped
```

As we can see here, this file is a x64 linux executable, not stripped. Nothing fancy.

### Play with the binary

```
./bomb
Welcome to my fiendish little bomb. You have 6 phases with
which to blow yourself up. Have a nice day!

sqdf

BOOM!!!
The bomb has blown up.
```

This binary has a prompt, and quit if the phase is not correct.

### Inspect the binary with radare2

{% img '2016-10-15-cmu_binary_bomb/main.png' %}

In this graph, we see that all the phase are functions,
all of them take an input from puts().
We can also guess that the binary can take an input file with all the passwords with the sym.imp.fopen().

Let's checkout the first phase.

### Phase 1

{% img '2016-10-15-cmu_binary_bomb/phase_1.png' %}

Ok, no comment.
Password: Border relations with Canada have never been better.

### Phase 2

{% img '2016-10-15-cmu_binary_bomb/phase_2.png' %}

This one is bigger, and begin with a call to the function read six numbers,
let's inspect this function:

{% img '2016-10-15-cmu_binary_bomb/read_six_numbers.png' %}

This function test if the input is formated with 6 digit and return them.

Now let's write a angr script to resolve this first phase.

```python
import angr

# The credit of this script belongs to Cory Duplantis (http://ctfhacker.com/)

start = 0x400f0a # Where the path begin
end = 0x400f3c   # Where we want to go
explode = (0x400f10, 0x400f20) # The addresses of explosions

proj = angr.Project('./bomb', load_options={'auto_load_libs':False}) # load the binary

state = proj.factory.blank_state(addr=start) # Create the path

# Push the 6 digit returned by our read_six_numbers function.
for i in xrange(6):
    state.stack_push(state.se.BVS('int_{}'.format(i), 4*8)) 

# Create and explore the function
path = proj.factory.path_group(state)
ex = path.explore(find=end, avoid=explode)

if ex.found:
    found = ex.found[0].state

    answer = []

    # Pop 3 64bit integer from the stack
    # we will convert it to 32 bit values

    for x in xrange(3):
        curr_int = found.se.any_int(found.stack_pop())

        answer.append(str(curr_int & 0xffffffff))
        answer.append(str(curr_int >> 32))

    print(" ".join(answer))
```

This script return: 1 2 4 8 16 32
And thats the correct answer.

Now the phase 3

### Phase 3

{% img '2016-10-15-cmu_binary_bomb/phase_3.png' %}

This one take they arguments with a scanf, let's see the fuction call :
```c
int sscanf(const char *str, const char *format, ...)
```
We assume that the function take the arguments of phase_3 and scan them with 0x4025CF.
Let's inspect the address 0x4025CF

{% img '2016-10-15-cmu_binary_bomb/part.png' %}

0x4025CF Is the Middle of the string used in read_six_number(), it take only 2 digits.

Now let's write a angr script to resolve this first phase.

```python
import angr

start = 0x400f63 # Where the path begin
end = 0x400fc9   # Where we want to go
explode = (0x400fc4, 0x400fad, 0x400f65) # The addresses of explosions

proj = angr.Project('./bomb', load_options={'auto_load_libs':False}) # load the binary

state = proj.factory.blank_state(addr=start) # Create the path

# Push the 2 digit returned by our scanff function.
for i in xrange(2):
    state.stack_push(state.se.BVS('int_{}'.format(i), 4*8))

# Create and explore the function
path = proj.factory.path_group(state)
ex = path.explore(find=end, avoid=explode)

if ex.found:
    found = ex.found[0].state

    answer = []
    
    found.stack_pop()

    curr_int = found.se.any_int(found.stack_pop())

    # Pop 1 64bit integer from the stack
    # we will convert it to 32 bit values
    answer.append(str(curr_int & 0xffffffff))
    answer.append(str(curr_int >> 32))

    print(" ".join(answer))
```

This script return: 1 311
And thats the correct answer.

### Phase 4

{% img '2016-10-15-cmu_binary_bomb/phase_4.png' %}

We can see the same function, and the same address as phase_3: sscanf and 0x4025CF
We also see a sub-function in this phase: func4(), let's see what's inside :

{% img '2016-10-15-cmu_binary_bomb/func4.png' %}

This is a recusive function, let's hope that angr can handle that !

```python
import angr

start = 0x40102c # Where the path begin
end = 0x40105d   # Where we want to go
explode = (0x401035, 0x401058) # The addresses of explosions

proj = angr.Project('./bomb', load_options={'auto_load_libs':False}) # load the binary

state = proj.factory.blank_state(addr=start) # Create the path

# Push the 2 digit returned by our scanff function.
for i in xrange(2):
    state.stack_push(state.se.BVS('int_{}'.format(i), 4*8))

# Create and explore the function
path = proj.factory.path_group(state)
ex = path.explore(find=end, avoid=explode)

if ex.found:
    found = ex.found[0].state

    found.stack_pop()
    
    answer = []
    ints = found.se.any_int(found.stack_pop())

    # Pop 1 64bit integer from the stack
    # we will convert it to 32 bit values
    answer.append(str(ints & 0xffffffff))
    answer.append(str(ints >> 32))

    print(" ".join(answer))r
```

The script return 7 0, which is a good answer.

### Phase 5

{% img '2016-10-15-cmu_binary_bomb/phase_5.png' %}

This function does not process the input, and take the raw string.
And we see that the function test if the string lenght is 6, now we know the input lenght, we can create the angr script.

```python
import angr

start = 0x401062 # Where the path begin
end = 0x4010ee   # Where we want to go
explode = (0x4010c6, 0x401084) # The addresses of explosions

proj = angr.Project('./bomb', load_options={'auto_load_libs':False}) # load the binary

state = proj.factory.blank_state(addr=start) # Create the path

password_addr = 0x100 # The arbitrary address of the string
password_lenght = 6   # The lenght of the string
password = state.se.BVS('password', password_lenght*8) #We create the symbolic bitvector string

state.memory.store(password_addr, password) # We store the BVS at the arbitrary address

# We set the constraint of printable chars to the input.
for i in xrange(password_lenght):
    m = state.memory.load(password_addr + i, 1)
    state.add_constraints(m >= 0x20)
    state.add_constraints(m <= '}')

# We put the strings in register
state.regs.rdi = password_addr

# Create and explore the function
path = proj.factory.path_group(state)
ex = path.explore(find=end, avoid=explode)

if ex.found:
    found = ex.found[0].state
    
    res = found.se.any_str(password) # Print the result string

    print(res)
```

The script return IONEFG, the good password
