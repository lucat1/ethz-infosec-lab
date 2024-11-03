# This file only contains code written by me.

a   = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
b   = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
p   = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
P_x = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
P_y = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
q   = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

nistp256_params = Schnorr_Params(a, b, p, P_x, P_y, q)
schnorr = Schnorr(nistp256_params)

signatures = []
max_messages = 5
for i in range(max_messages):
    json_send({ "command": "get_signature", "msg": f"{'A' * i}" })
    chall = json_recv()
    signatures.append(chall)

leaked_bits = 128
scale = 2**(leaked_bits + 1)
# should be (schnorr.q**max_messages)/scale but we can just avoid multiplying M
# for scale. and q**n mod q = q
det = schnorr.q
# M = lambda
M = schnorr.Z_q(det * sqrt((max_messages + 1) / (2 * pi * e)))

B = schnorr.q * matrix(ZZ, matrix.identity(max_messages + 2))
for i in range(max_messages):
    B[max_messages, i] = signatures[i]["h"]

for i in range(max_messages):
    a = signatures[i]["nonce"]
    s = signatures[i]["s"]
    uconst = schnorr.Z_q(a - s)
    B[max_messages+1,i] = uconst
B *= scale
B[max_messages, max_messages] = 1
B[max_messages+1, max_messages+1] = M

sol = B.LLL()

for i in range(B.nrows()):
    diff = M - sol.rows()[i][-1]
    if diff != 0:
        continue

    f = sol.rows()[i]
    # should be u[max_messages] - f[max_messages]
    # but u[..] will always be 0
    privkey = schnorr.Z_q(-f[max_messages])
    msg = "gimme the flag"
    h, s = schnorr.Sign(privkey, msg)

    json_send({ "command": "solve", "h": int(h), "s": int(s) })
    res = json_recv()
    if "flag" in res:
        print(res["flag"])
        break
