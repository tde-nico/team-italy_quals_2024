import pwn

with open('forgot', 'rb') as f:
	code = f.read()

script = '''
b *0x400000
b *0x40008a
b *0x40009c
'''

out = pwn.debug_shellcode(code, gdbscript=script, vma=0x400000, api=True, arch='amd64')

out.interactive()

# TeamItaly{secret_for_revving:do_not_rev_842923f7}
