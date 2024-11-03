# This file only contains code written by me.

class ECDSA2():
    def KeyGen(self) -> Tuple[IntegerMod_int, Point]:
        x = 0
        while x == 0:
            x = secrets.randbelow(self.q)
        x = self.Z_q(x)
        Q = x * self.P
        return x, Q

    def Sign_FixedNonce(self, nonce: IntegerMod_int, privkey: IntegerMod_int, msg: str) -> Tuple[IntegerMod_int, IntegerMod_int]:
        h = bits_to_int(hash_message_to_bits(msg), self.q)

        r, s = (0,0)
        while True:
            r = self.Z_q((nonce * self.P).x)
            s = inverse_mod(nonce, self.q) * (h**2 + 1337 * privkey * r)

            if r != 0 and s != 0:
                break

        return (r, s)

    def Sign(self, privkey, msg) -> Tuple[IntegerMod_int, IntegerMod_int]:
        h = bits_to_int(hash_message_to_bits(msg), self.q)

        r, s = (0,0)
        while True:
            nonce = randint(1, self.q - 1)
            r = self.Z_q((nonce * self.P).x)
            s = self.Z_q(inverse_mod(nonce, self.q) * (h**2 + 1337 * privkey * r))

            if r != 0 and s != 0:
                break

        return (r, s)

    def Verify(self, pubkey: Point, msg: str, r: IntegerMod_int, s: IntegerMod_int) -> bool:
        if r < 1 or r > self.q-1 or s < 1 or s > self.q-1:
            return False

        w = inverse_mod(s, self.q)
        h = bits_to_int(hash_message_to_bits(msg), self.q)
        u_1 = self.Z_q(w * h**2)
        u_2 = self.Z_q(w * r * 1337)
        Z = u_1 * self.P + u_2 * pubkey
        return self.Z_q(Z.x) == r
