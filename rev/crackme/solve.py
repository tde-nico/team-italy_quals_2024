from Crypto.Cipher import Blowfish
from Crypto.Util.number import long_to_bytes, bytes_to_long
from functools import reduce
from z3 import *

enc_flag = [
	0x85, 0x49, 0x30, 0x1B, 0x70, 0xD1, 0x09, 0x41, 0x11, 0x0C, 
	0x25, 0xCE, 0x5D, 0x72, 0xAD, 0xCE, 0xAD, 0x84, 0xDF, 0xF7, 
	0xCD, 0x0D, 0x99, 0xCF, 0xFA, 0x7E, 0x78, 0x04, 0x1D, 0xA2, 
	0xD1, 0x40, 0x09, 0x3A, 0x7A, 0x34, 0x7F, 0xC1, 0x29, 0xF2, 
	0x0C, 0x4A, 0x40, 0xF9, 0x25, 0xC0, 0xB2, 0xAC
]

chunks = [
	0x40020008000, 0x4A0000000000, 0x100840, 0x100000204, 0x6000001000,
	0x200000000000108, 0x4100000020000, 0x1000000040000010,
	0x7FE69F07D2F3BF98, 0x0A8E792F8160B2A34, 0x1F57442B9A98489B,
	0x0B04D3B5C71041323, 0x82CD3EEE60BEECF3, 0x31ED876EC02FC7E2,
	0x8902DFEB67AF8F0D, 0x8806874A9F84BA83, 0x21FCA3F1F3EA002D,
	0x847BE631607B8AF8, 0x6E9F1F4359E49065, 0x9A3871279981E8AF,
	0x0AFAEF18CFDA7C203, 0x0F2B14D6FE4F7C02A, 0x4629F58473C526B5,
	0x0D17677BB16D2F09, 0x462E8E777A36C6F2, 0x2611B83DA41986D8,
	0x521341D7D23B7703, 0x1036FC37FC3EFC07, 0x0E2FF993635B1A34B,
	0x0FCE42CEE83486E14, 0x613E190E50F87C92, 0x72273FE443252ED6,
	0x8BAC6EC4C49DC101, 0x892C51C2D24BB36D, 0x0A93010215AD7005B,
	0x58E8B66042CED20F, 0x0AAE92EBE8125A89B, 0x0A454E2AC134630E0,
	0x9EA5FA07DD7C0377, 0x0E884FDF0E0BFB1BA, 0x0B40398B93F2DE802,
	0x137F9410DEA5D5B7, 0x6B3E2D4BE901D301, 0x645A469944E94EA4,
	0x7F1C62EB8893FB0E, 0x2642F58CFF4AA1BB, 0x496CF2110637556E,
	0x8EEE3B18172D577A, 0x9EAAD18E7D1C1E2, 0x86470BEAD52C6BB,
	0x7A74A1256C72ACAC, 0x0CB9F0594D1BC23B7, 0x7F597A434C90CE81,
	0x0A9FF33A84B5300F1, 0x1BE38E14EE101EDF, 0x8872B433AEFD7F08,
	0x0A59AB033F8D5CED3, 0x2C6C13C80F2BD7FE, 0x0D5CB1F6009F358A4,
	0x0D332F75763C5D761, 0x56DE2B1388EF37AC, 0x14B8B771174A5A63,
	0x220272273439A504, 0x0BC516C8486EB48E9, 0x0DAEDCB293C98F5AF,
	0x977745E0FB3EAFE0, 0x0A32CFA50057AE002, 0x1E650B44FF2B19F0,
	0x721E4BB7519D8171, 0x0A27C4E0EF53C58B4, 0x0A479C998F7B72EF8,
	0x0E4ABE2DB6C4C6702,
]

s = Solver()
KEY = [BitVec(f'k_{i}', 8) for i in range(8)]


def decrypt(key: bytes, data: list[int]) -> list[int]:
	chunk = b''.join(long_to_bytes(chunk) for chunk in data)
	cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv=bytes(8))
	decrypted = cipher.decrypt(chunk)
	return [bytes_to_long(decrypted[i:i+8]) for i in range(0, len(decrypted), 8)]


def set_constraint(key: int, data: list[int]):
	for i, mask in enumerate(data):
		octet = 0
		while mask:
			if mask & 1:
				key ^= ((KEY[octet >> 3] >> (octet & 7)) & 1) << (i & 7)
			mask >>= 1
			octet += 1
	s.add(key == 0)


decrypted_chunks = [chunks[:8]]
keys = []

for idx in range(8, len(chunks)-8, 8):
	for key in range(256):
		decrypted_chunk = decrypt(bytes([key] * 4), chunks[idx:idx+8])
		dec = reduce(int.__or__, decrypted_chunk)
		if dec.bit_count() <= 24:
			decrypted_chunks.append(decrypted_chunk)
			keys.append(key)
			break


for key in range(256):
	decrypted_chunk = decrypt(bytes([key] * 4), chunks[-8:])
	if decrypted_chunk == [0xDEADBEEF, 0xC0FFEBABE, 0xBAAD1337, 0] * 2:
		keys.append(key)


for i in range(len(keys)):
	set_constraint(keys[i], decrypted_chunks[i])



print('Checking...')
check = s.check()
print(check)
if check != sat:
	exit(1)

m = s.model()
key = [m[i].as_long() for i in KEY]

swap_chunks = lambda x: b''.join([bytes(x[i:i+8])[::-1] for i in range(0, len(x), 8)])
chunk = swap_chunks(enc_flag)
cipher = Blowfish.new(bytes(key), Blowfish.MODE_CBC, iv=bytes(8))
decrypted = cipher.decrypt(chunk)
flag =  swap_chunks(decrypted)
print(flag)

# TeamItaly{h3re's_my_numb3r_so_e2338642b7e83ab0}
