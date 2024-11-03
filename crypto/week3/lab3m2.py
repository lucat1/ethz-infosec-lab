# This file only contains code written by me.

a   = 17
b   = 1
n   = 0x579d4e9590eeb88fd1b640a4d78fcf02bd5c375351cade76b69561d9922d3070d479a67192c67265cf9ae4a1efde400ed40757b0efd2912cbda49e60c83a1ddd361d31859bc4e206158491a528bd46d0b41c6e8d608c586a0788b8027f0f796e9e077766f83683fd52965101bb7bf9fd90c9e9653f02fada8bf10d62bc325ef
P_x = 0x54d73da0d9a78dc3a7914c1677def57a6f4e74c424e574f93e5252885833f988e27517b5b4da981dd69fc242d5c0dc3d17e6129c6e4af4cd2cfb8200ce49c17381d80e2dd9e3d5f0517e720a7db3d903ca11b33069edffbba39f71f6b5f8d698ab1a8170017ed6d1675175e6e54b6ebbb94da460d623b87669c8686d2d4b856
P_y = 0x30ba788b53a932136fdfdd0f82d6328a1bbb29368aa22d8fe2c2ae16a7d466f1a8d0e4b0fe725ed049c9ae41090e521add6e7e1d5f7f498942bae2a997f2f55bdd7959f5d72c3d781d657cb0feb81e7e15fd7065b3ce6f5b5cd5218e8c101841e600c1920d4e8fb3dd3aaf2458861015f652babcd32be90f46a8cdbc54edd1
curve = EllipticCurve(Zmod(n), [a, b])

json_send({ "command": "get_ciphertext" })
chall = json_recv()
ciphertext = chall["ciphertext"]
ciphertext = bytearray.fromhex(ciphertext)

# the y always leaks cause the concatenation of x and y is way
# longer than the 16 bytes needed for the encoding of the secret
cipher_bytes = len(ciphertext)
cipher_bits = cipher_bytes * 8
half_bytes = cipher_bytes // 2
half_bits = half_bytes * 8
y_coord = int.from_bytes(ciphertext[half_bytes:])
leaked_x = int.from_bytes(ciphertext[16:half_bytes])
xored_x = ciphertext[:16]
xored_x_bits = len(xored_x) * 8
X = 2 ** (xored_x_bits)
x_offset = 2 ** (half_bits - xored_x_bits)
xored_x = int.from_bytes(xored_x)

k = Zmod(n)['k'].gen()
# this comes from the elliptic curve formula:
# y^2 = x^3 + ax + b
# overwriting x = leaked_x + k * x_offset
x = (leaked_x + k * x_offset)
F_x = x** 3 + a * x + b - y_coord ** 2
F_x = F_x.monic().change_ring(ZZ)

# from now on it's just lab3m0

size = F_x.degree()
B = matrix(ZZ, size+1, size+1)

for i in range(size):
    B[i, i] = n * X ** i

for j in range(size):
    B[size, j] = F_x[j] * X ** j

B[size, size] = X**size

B = B.LLL()
# ty https://ask.sagemath.org/question/10734/polynomial-coefficient-vector-to-symbolic-polynomial/
# and example 19.1.6
x = ZZ['x'].gen()
G_x = sum([(b / X ** a) * x ** a for a,b in enumerate(B.rows()[0])])

roots = G_x.roots()
roots = list(map(lambda x: int(x[0]), roots))

for root in roots:
    print("Trying root", root)
    secret = (xored_x ^ root).to_bytes(xored_x_bits // 8, byteorder='big')

    json_send({ "command": "solve", "plaintext": secret.decode() })
    res = json_recv()
    if "flag" in res:
        print(res["flag"])
        break
