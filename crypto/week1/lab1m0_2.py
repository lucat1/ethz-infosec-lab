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
pk = json_recv()
pubkey = Point(nistp256_params.curve, pk["x"], pk["y"])

done = 0
while True:
    json_send({ "command": "get_signature" })
    chall = json_recv()
    # print(chall)
    correct = ecdsa2.Verify(pubkey, chall["msg"], chall["r"], chall["s"])
    json_send({ "command": "solve", "b": 1 if correct else 0 })
    ans = json_recv()
    print(ans["res"])
    if ans["res"].startswith("Good!"):
        done += 1
        if done == 128:
            break

json_send({ "command": "flag" })
print(json_recv()["flag"])
