"""Minimal affine P-256 arithmetic for the isolated key-recovery demo. Not production cryptography."""

import math

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


def point_neg(point):
    if point is None:
        return None
    x, y = point
    return (x, (-y) % P)


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


def bsgs(target, bound: int):
    """Find d in [1, bound) such that d*G is target, or return None."""
    if bound <= 1:
        return None

    width = math.isqrt(bound - 1) + 1
    baby_steps = {}
    point = None
    for scalar in range(width):
        baby_steps[point] = scalar
        point = point_add(point, G)

    giant_step = point_neg(scalar_mul(width, G))
    current = target
    for giant_index in range((bound + width - 1) // width):
        baby_index = baby_steps.get(current)
        if baby_index is not None:
            scalar = giant_index * width + baby_index
            if 1 <= scalar < bound and scalar_mul(scalar, G) == target:
                return scalar
        current = point_add(current, giant_step)
    return None
