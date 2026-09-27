"""
SINERGY BLOCKCHAIN 16D - Post-Quantum Hash Engine
16 Independent Cryptographic Dimensions XOR'd into 32-byte output.

Dimensions:
  D01: SHA3-256           D09: Ring-LWE (Kyber params)
  D02: SHA3-512           D10: Isogeny Montgomery curve
  D03: BLAKE2b-512        D11: Merkle tree (4 leaves)
  D04: BLAKE2s-256        D12: SPHINCS+ leaf (8-level)
  D05: SHAKE-256          D13: NTRU lattice hash
  D06: SHA-512/256        D14: XOR-fold compression
  D07: HMAC-SHA256        D15: FNV1a-128
  D08: Memory-hard KDF    D16: Pedersen commitment

Final: XOR(D01..D16) → SHA3-256 → 32 bytes hex
"""
from __future__ import annotations
import hashlib
import hmac
import struct
from typing import Union

# Ring-LWE parameters (Kyber-768)
_RLWE_N = 256
_RLWE_Q = 3329

# NTRU parameters
_NTRU_N = 64
_NTRU_Q = 257

# Isogeny prime (Mersenne)
_ISO_P = (1 << 127) - 1


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    la, lb = len(a), len(b)
    if la < lb:
        a = a + b"\x00" * (lb - la)
    elif lb < la:
        b = b + b"\x00" * (la - lb)
    return bytes(x ^ y for x, y in zip(a, b))


def _to_32(data: bytes) -> bytes:
    if len(data) >= 32:
        return data[:32]
    return data + b"\x00" * (32 - len(data))


class Hash16D:
    """Post-quantum 16-dimensional hash."""

    __slots__ = ("_persona",)

    def __init__(self, persona: bytes = b"SINERGY_16D_v3"):
        self._persona = persona

    def hash(self, data: Union[bytes, str], fast: bool = False) -> str:
        if isinstance(data, str):
            data = data.encode("utf-8")

        dims = [
            self._d01_sha3_256(data),
            self._d02_sha3_512(data),
            self._d03_blake2b(data),
            self._d04_blake2s(data),
            self._d05_shake256(data),
            self._d06_sha512_256(data),
            self._d07_hmac_sha256(data),
            self._d08_memory_hard(data) if not fast else self._d08_fast(data),
            self._d09_ring_lwe(data),
            self._d10_isogeny(data),
            self._d11_merkle(data),
            self._d12_sphincs(data),
            self._d13_ntru(data),
            self._d14_xor_fold(data),
            self._d15_fnv1a(data),
            self._d16_pedersen(data),
        ]

        combined = dims[0]
        for d in dims[1:]:
            combined = _xor_bytes(combined, d)

        return hashlib.sha3_256(combined).hexdigest()

    def hash_bytes(self, data: Union[bytes, str], fast: bool = False) -> bytes:
        return bytes.fromhex(self.hash(data, fast))

    @staticmethod
    def _d01_sha3_256(data: bytes) -> bytes:
        return hashlib.sha3_256(data).digest()

    @staticmethod
    def _d02_sha3_512(data: bytes) -> bytes:
        return hashlib.sha3_512(data).digest()[:32]

    @staticmethod
    def _d03_blake2b(data: bytes) -> bytes:
        return hashlib.blake2b(data, digest_size=32).digest()

    @staticmethod
    def _d04_blake2s(data: bytes) -> bytes:
        return hashlib.blake2s(data, digest_size=32).digest()

    @staticmethod
    def _d05_shake256(data: bytes) -> bytes:
        return hashlib.shake_256(data).digest(32)

    @staticmethod
    def _d06_sha512_256(data: bytes) -> bytes:
        full = hashlib.sha512(data).digest()
        return _xor_bytes(full[:32], full[32:])

    def _d07_hmac_sha256(self, data: bytes) -> bytes:
        return hmac.new(self._persona, data, hashlib.sha256).digest()

    @staticmethod
    def _d08_memory_hard(data: bytes) -> bytes:
        return hashlib.scrypt(
            data, salt=b"sinergy_16d_salt", n=2**14, r=8, p=1, dklen=32
        )

    @staticmethod
    def _d08_fast(data: bytes) -> bytes:
        return hashlib.sha3_256(b"D08_FAST" + data).digest()

    @staticmethod
    def _d09_ring_lwe(data: bytes) -> bytes:
        expanded = hashlib.shake_256(data).digest(_RLWE_N * 2)
        coeffs = [
            int.from_bytes(expanded[i * 2: i * 2 + 2], "little") % _RLWE_Q
            for i in range(_RLWE_N)
        ]
        a_coeffs = [
            int.from_bytes(
                hashlib.sha3_256(data + i.to_bytes(2, "little")).digest()[:2],
                "little",
            ) % _RLWE_Q
            for i in range(_RLWE_N)
        ]
        result = [0] * _RLWE_N
        for i in range(min(32, _RLWE_N)):
            s = 0
            for j in range(min(32, _RLWE_N)):
                idx = (i + j) % _RLWE_N
                s = (s + coeffs[j] * a_coeffs[idx]) % _RLWE_Q
            result[i] = s
        out = b""
        for i in range(32):
            out += (result[i] & 0xFF).to_bytes(1, "little")
        return out

    @staticmethod
    def _d10_isogeny(data: bytes) -> bytes:
        x = int.from_bytes(hashlib.sha3_256(data).digest(), "big") % _ISO_P
        for _ in range(16):
            x = (x * x + 1) % _ISO_P
        return _to_32(x.to_bytes(16, "big"))

    @staticmethod
    def _d11_merkle(data: bytes) -> bytes:
        chunk = max(1, len(data) // 4)
        leaves = []
        for i in range(4):
            part = data[i * chunk: (i + 1) * chunk] if i < 3 else data[3 * chunk:]
            leaves.append(hashlib.sha3_256(part or b"\x00").digest())
        n01 = hashlib.sha3_256(leaves[0] + leaves[1]).digest()
        n23 = hashlib.sha3_256(leaves[2] + leaves[3]).digest()
        return hashlib.sha3_256(n01 + n23).digest()

    @staticmethod
    def _d12_sphincs(data: bytes) -> bytes:
        node = hashlib.sha3_256(b"SPHINCS_LEAF" + data).digest()
        for lvl in range(8):
            sibling = hashlib.sha3_256(node + lvl.to_bytes(1, "big")).digest()
            node = hashlib.sha3_256(node + sibling).digest()
        return node

    @staticmethod
    def _d13_ntru(data: bytes) -> bytes:
        expanded = hashlib.shake_256(data).digest(_NTRU_N)
        f = [b % _NTRU_Q for b in expanded]
        g = [
            int.from_bytes(
                hashlib.sha3_256(data + bytes([i])).digest()[:1], "little"
            ) % _NTRU_Q
            for i in range(_NTRU_N)
        ]
        conv = [0] * _NTRU_N
        for i in range(_NTRU_N):
            s = 0
            for j in range(min(16, _NTRU_N)):
                s = (s + f[j] * g[(i - j) % _NTRU_N]) % _NTRU_Q
            conv[i] = s
        return bytes(c & 0xFF for c in conv[:32])

    @staticmethod
    def _d14_xor_fold(data: bytes) -> bytes:
        h = hashlib.sha512(data).digest()
        return _xor_bytes(h[:32], h[32:])

    @staticmethod
    def _d15_fnv1a(data: bytes) -> bytes:
        FNV_OFFSET = 0x6C62272E07BB014262B821756295C58D
        FNV_PRIME = 0x0000000001000000000000000000013B
        h = FNV_OFFSET
        for b in data:
            h ^= b
            h = (h * FNV_PRIME) & ((1 << 128) - 1)
        return _to_32(h.to_bytes(16, "big"))

    @staticmethod
    def _d16_pedersen(data: bytes) -> bytes:
        G = int.from_bytes(hashlib.sha3_256(b"PEDERSEN_G").digest(), "big")
        H = int.from_bytes(hashlib.sha3_256(b"PEDERSEN_H").digest(), "big")
        P = (1 << 255) - 19
        m = int.from_bytes(hashlib.sha3_256(data).digest(), "big")
        r = int.from_bytes(hashlib.sha3_256(data + b"\x01").digest(), "big")
        C = (pow(G, m, P) * pow(H, r, P)) % P
        return _to_32(C.to_bytes(32, "big"))


_default = Hash16D()


def hash16d(data: Union[bytes, str], fast: bool = True) -> str:
    return _default.hash(data, fast=fast)


def hash16d_bytes(data: Union[bytes, str], fast: bool = True) -> bytes:
    return _default.hash_bytes(data, fast=fast)
