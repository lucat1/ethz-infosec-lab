# This file only contains code written by me.

N_BIT_LENGTH = 1024
X = 2 ** (N_BIT_LENGTH // 8)
secret_len = 16

json_send({ "command": "get_pubkey" })
pubkey = json_recv()
N = pubkey["n"]
e = pubkey["e"]

json_send({ "command": "get_ciphertext" })
chall = json_recv()
cipher = chall["ciphertext"]
c = ZZ('0x' + cipher)

# reverse the padding, kepping \x00 bytes where the secret is
padding_secret_len = 1 + secret_len # one \x00 byte + 16 bytes for the hex encoding of the secret
to_add = len(cipher) // 2 - padding_secret_len # the number of padding bytes
constant = bytes([to_add] * to_add)
constant = int.from_bytes(constant, byteorder='big')
padding_bits = to_add * 8

x = Zmod(N)['x'].gen()
# x has to be multiplied by 2*bitlen because x's bits are the MSB
F_x = (constant + x * 2 ** padding_bits) ** e - c
F_x = F_x.monic().change_ring(ZZ)

size = F_x.degree()
B = matrix(ZZ, size+1, size+1)

for i in range(size):
    B[i, i] = N * X ** i

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
    message = root.to_bytes(secret_len, byteorder='big')

    json_send({ "command": "solve", "message": message.decode() })
    res = json_recv()
    if "flag" in res:
        print(res["flag"])
        break
