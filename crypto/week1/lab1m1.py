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

json_send({ "command": "get_signature", "msg": msg })
chall = json_recv()
assert chall['r'] == r
s = chall['s']

k1 = inverse_mod(nonce, ecdsa2.q)
privkey = (s - k1 * h**2) / (k1 * 1337 * r)
assert privkey % ecdsa2.q == privkey

r, s = ecdsa2.Sign(privkey, "gimme the flag")
json_send({ "command": "solve", "r": int(r), "s": int(s) })
print(json_recv()["flag"])
