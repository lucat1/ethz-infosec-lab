# This file only contains code written by me.

a   = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
b   = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
p   = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
P_x = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
P_y = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
q   = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

nistp256_params = Schnorr_Params(a, b, p, P_x, P_y, q)
schnorr = Schnorr(nistp256_params)

def guess_privkey(signatures):
    max_messages = len(signatures)
    leaked_bits = 7
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
        s = signatures[i]["s"]
        uconst = schnorr.Z_q(0 - s)
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
        return privkey
    return None

# 4000 works best after some trials
min_requests = 4000
max_requests = 20_000
i = 0
msgs = []
n = 80

for _ in range(min_requests):
    json_send({ "command": "get_signature" })
    chall = json_recv()
    i += 1
    heappush(msgs, (chall["time"], chall["msg"], chall))

while i < max_requests:
    items = nsmallest(n, msgs)
    items = list(map(lambda x: x[2], items))
    privkey = guess_privkey(items)

    if privkey is not None:
        msg = "gimme the flag"
        h, s = schnorr.Sign(privkey, msg)
        json_send({ "command": "solve", "h": int(h), "s": int(s) })
        ans = json_recv()
        if "flag" in ans:
            print(i)
            print(ans["flag"])
            break

    # Let's get n more messages so hopefully we find ones with more zero bits
    for _ in range(n):
        json_send({ "command": "get_signature" })
        chall = json_recv()
        i += 1
        heappush(msgs, (chall["time"], chall["msg"], chall))
