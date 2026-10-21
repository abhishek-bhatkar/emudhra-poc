"""
Minimal pure-Python NIST P-256 (secp256r1) arithmetic.

Only what we need: scalar multiplication of the generator, to (a) derive the
public key of a deliberately-chosen weak private scalar and (b) brute-force
recover that scalar from a public key -- exactly the trivial recovery that
made the real eMudhra/emSign intermediates compromised.

Coordinates are affine tuples (x, y); the point at infinity is None.
This is NOT production crypto code -- it is deliberately slow and simple.
"""

P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

G = (GX, GY)


def _inv(a: int) -> int:
    return pow(a, -1, P)


def point_add(p1, p2):
    """Add two points on P-256 (affine)."""
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        # doubling: lambda = (3x^2 + a) / (2y)
        lam = (3 * x1 * x1 + A) * _inv(2 * y1) % P
    else:
        lam = (y2 - y1) * _inv(x2 - x1) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def scalar_mul(d: int, point=G):
    """Double-and-add scalar multiplication."""
    d %= N
    result = None
    addend = point
    while d:
        if d & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        d >>= 1
    return result
