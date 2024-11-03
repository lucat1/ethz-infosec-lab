# This file only contains code written by me.

a   = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
b   = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
p   = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
P_x = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
P_y = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
q   = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
nistp256_params = ECDSA2_Params(a, b, p, P_x, P_y, q)
ecdsa2 = ECDSA2(nistp256_params)

json_send({ "command": "get_pubkey" })
chall = json_recv()
pubkey = Point(nistp256_params.curve, chall["x"], chall["y"])

nonce = ecdsa2.Z_q(bits_to_int(hash_message_to_bits("Now you're just some value that I used to nonce"), q))
msg = "please, gimme the flag"
h = bits_to_int(hash_message_to_bits(msg), ecdsa2.q)

r = ecdsa2.Z_q((nonce * ecdsa2.P).x)

hash_candidate = {}

msg1 = "please, gimme the flag"
msg2 = "pretty please, gimme the flag"

def H(msg):
    return bits_to_int(hash_message_to_bits(msg), ecdsa2.q)

while True:
    json_send({ "command": "get_signature", "msg": msg1 })
    chall1 = json_recv()
    json_send({ "command": "get_signature", "msg": msg2 })
    chall2 = json_recv()

    r1 = chall1["r"]
    s1 = chall1["s"]
    r2 = chall2["r"]
    s2 = chall2["s"]

    if r1 == r2:
        break

h1 = bits_to_int(hash_message_to_bits(msg1), ecdsa2.q)
h2 = bits_to_int(hash_message_to_bits(msg2), ecdsa2.q)
k1 = (s1 - s2) / (h1**2 - h2**2)

privkey1 = (s1 - k1 * h1**2) / (k1 * 1337 * r1)
privkey2 = (s2 - k1 * h2**2) / (k1 * 1337 * r2)
assert privkey1 == privkey2
privkey = privkey1

r, s = ecdsa2.Sign(privkey, "gimme the flag")
json_send({ "command": "solve", "r": int(r), "s": int(s) })
print(json_recv()["flag"])
