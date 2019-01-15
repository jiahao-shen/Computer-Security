"""
@project: Computer-Security
@author: sam
@file rsa.py
@ide: PyCharm
@time: 2018-12-24 10:14:31
@blog: https://jiahaoplus.com
"""
from random import randint
from math import floor, log, gcd


def multiplicative_inverse(a, b):
    """Solve Multiplicative Inverse
    a * x === 1 (mod b)
    :param a:
    :param b:
    :return: x
    """
    r1, r2 = b, a
    t1, t2 = 0, 1
    while r2 > 0:
        q = r1 // r2
        r = r1 - q * r2
        r1 = r2
        r2 = r

        t = t1 - q * t2
        t1 = t2
        t2 = t

    if t1 < 0:
        t1 = t1 + b

    return t1


def fast_pow_mod(a, b, c):
    """Fast Power Mod Method
    :param a:
    :param b:
    :param c:
    :return: (a ^ b) mod c
    """
    result = 1
    while b != 0:
        if b & 1:
            result = (result * a) % c
        b >>= 1
        a = (a * a) % c
    return result


def miller_rabin(a, p):
    """Miller Rabin Method
    :param a:
    :param p:
    :return: Boolean
    """
    if p == 1:
        return False
    if p == 2:
        return True

    # Fermat's Little Theorem
    # If p is prime, for all integer a, a ^ (p - 1) mod p == 1
    # To exclude composite number
    if fast_pow_mod(a, p - 1, p) != 1:
        return False

    # Decomposition p - 1 into (2 ^ k) * t
    k = int(floor(log(p - 1, 2)))
    t = 1
    while k > 0:
        t = (p - 1) // (2 ** k)
        if (p - 1) % (2 ** k) == 0 and t % 2 == 1:
            break
        k = k - 1

    # Quadratic Detection Theorem
    # Solve a ^ ((2 ^ k) * t) mod p
    tmp = fast_pow_mod(a, t, p)
    for i in range(k):
        # Check whether tmp equals p - 1 or 1
        if tmp == p - 1 or tmp == 1:
            return True
        tmp = (tmp ** 2) % p

    if tmp == 1:
        return True

    return False


def check_prime(p, k=8):
    """Check whether p is prime or not
    :param p: number
    :param k: Check times(default 8)
    :return: Boolean
    """
    if k < 0:
        k = 8

    while k > 0:
        a = randint(1, p - 1)
        if not miller_rabin(a, p):
            return False
        k = k - 1
    return True


def generate_big_prime(length=1024):
    """Generate a big prime number
    :param length: default 1024
    :return:
    """
    while True:
        num = randint(0, 1 << length)
        if num % 2 == 0:
            num = num + 1
        if check_prime(num):
            return num


def generate_key():
    """Generate RSA KEY
    :return: rsa_key('private_key', 'public_key')
    """
    p = generate_big_prime()
    q = generate_big_prime()
    n = p * q
    phi = (p - 1) * (q - 1)

    while True:
        e = randint(2, phi)
        if gcd(e, phi) == 1:
            break

    d = multiplicative_inverse(e, phi)

    key = {'public': [e, n], 'private': [d, n]}
    return key


def encryption(message, public_key):
    """Encryption
    :param message:
    :param public_key:
    :return: C = M ^ e mod n
    """
    result = fast_pow_mod(message, public_key[0], public_key[1])
    return result


def decryption(message, private_key):
    """Decryption
    :param message:
    :param private_key:
    :return: M = C ^ d mod n
    """
    result = fast_pow_mod(message, private_key[0], private_key[1])
    return result


def transform_string_to_int(message):
    """Transform Text to Int
    Transform String to Bytes, then to the Hex, finally to Int
    :param message: String
    :return: Int
    """
    return int(message.encode().hex(), 16)


def transform_int_to_string(message):
    """Transform Int to Text
    Transform Int to Hex, then to Bytes, finally to String
    :param message: Int
    :return: String
    """
    return bytes.fromhex(hex(message)[2:]).decode()


if __name__ == '__main__':
    print('Generating RSA KEY...')
    rsa_key = generate_key()
    print('Finished')
    while True:
        M = transform_string_to_int(input('Please input message : '))
        C = encryption(M, rsa_key['public'])
        print('After encryption data :', C)
        M = transform_int_to_string(decryption(C, rsa_key['private']))
        print('After decryption data :', M)
        print('--------------------------------')
