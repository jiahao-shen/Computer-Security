"""
@project: Computer-Security
@author: sam
@file md5.py
@ide: PyCharm
@time: 2018-12-24 16:57:28
@blog: https://jiahaoplus.com
"""
import numpy as np

# Initialization Constants
A = 0x67452301
B = 0xefcdab89
C = 0x98badcfe
D = 0x10325476

S = np.array([[7, 12, 17, 22],
              [5, 9, 14, 20],
              [4, 11, 16, 23],
              [6, 10, 15, 21]])

result = [A, B, C, D]

convert_to_hex = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F']


def F(x, y, z):
    """F(x, y, z) = (x & y) | ((~x) & z)
    :param x: Int
    :param y: Int
    :param z: Int
    :return: Int
    """
    return (x & y) | ((~x) & z)


def G(x, y, z):
    """G(x, y, z) = (x & z) | (y & (~Z))
    :param x: Int
    :param y: Int
    :param z: Int
    :return: Int
    """
    return (x & z) | (y & (~z))


def H(x, y, z):
    """H(x, y, z) = x ^ y ^ z
    :param x: Int
    :param y: Int
    :param z: Int
    :return: Int
    """
    return x ^ y ^ z


def I(x, y, z):
    """I(x, y, z) = y ^ (x | (~z))
    :param x: Int
    :param y: Int
    :param z: Int
    :return: Int
    """
    return y ^ (x | (~z))


def FF(a, b, c, d, x, s, ac):
    """
    :param a: Int
    :param b: Int
    :param c: Int
    :param d: Int
    :param x: Int
    :param s: Int
    :param ac: Int
    :return: Int
    """
    a += (F(b, c, d) & 0xFFFFFFFF) + x + ac
    a = ((a & 0xFFFFFFFF) << s | (a & 0xFFFFFFFF) >> (32 - s))
    a += b
    return a & 0xFFFFFFFF


def GG(a, b, c, d, x, s, ac):
    """
    :param a: Int
    :param b: Int
    :param c: Int
    :param d: Int
    :param x: Int
    :param s: Int
    :param ac: Int
    :return: Int
    """
    a += (G(b, c, d) & 0xFFFFFFFF) + x + ac
    a = ((a & 0xFFFFFFFF) << s | (a & 0xFFFFFFFF) >> (32 - s))
    a += b
    return a & 0xFFFFFFFFF


def HH(a, b, c, d, x, s, ac):
    """
    :param a: Int
    :param b: Int
    :param c: Int
    :param d: Int
    :param x: Int
    :param s: Int
    :param ac: Int
    :return: Int
    """
    a += (H(b, c, d) & 0xFFFFFFFF) + x + ac
    a = ((a & 0xFFFFFFFF) << s | (a & 0xFFFFFFFF) >> (32 - s))
    a += b
    return a & 0xFFFFFFFFF


def II(a, b, c, d, x, s, ac):
    """
    :param a: Int
    :param b: Int
    :param c: Int
    :param d: Int
    :param x: Int
    :param s: Int
    :param ac: Int
    :return: Int
    """
    a += (I(b, c, d) & 0xFFFFFFFF) + x + ac
    a = ((a & 0xFFFFFFFF) << s | (a & 0xFFFFFFFF) >> (32 - s))
    a += b
    return a & 0xFFFFFFFFF


def trans(groups):
    """
    :param groups: Int[]
    :return:
    """
    a, b, c, d = result
    # Round 1
    a = FF(a, b, c, d, groups[0], S[0, 0], 0xd76aa478)
    d = FF(d, a, b, c, groups[1], S[0, 1], 0xe8c7b756)
    c = FF(c, d, a, b, groups[2], S[0, 2], 0x242070db)
    b = FF(b, c, d, a, groups[3], S[0, 3], 0xc1bdceee)

    a = FF(a, b, c, d, groups[4], S[0, 0], 0xf57c0faf)
    d = FF(d, a, b, c, groups[5], S[0, 1], 0x4787c62a)
    c = FF(c, d, a, b, groups[6], S[0, 2], 0xa8304613)
    b = FF(b, c, d, a, groups[7], S[0, 3], 0xfd469501)

    a = FF(a, b, c, d, groups[8], S[0, 0], 0x698098d8)
    d = FF(d, a, b, c, groups[9], S[0, 1], 0x8b44f7af)
    c = FF(c, d, a, b, groups[10], S[0, 2], 0xffff5bb1)
    b = FF(b, c, d, a, groups[11], S[0, 3], 0x895cd7be)

    a = FF(a, b, c, d, groups[12], S[0, 0], 0x6b901122)
    d = FF(d, a, b, c, groups[13], S[0, 1], 0xfd987193)
    c = FF(c, d, a, b, groups[14], S[0, 2], 0xa679438e)
    b = FF(b, c, d, a, groups[15], S[0, 3], 0x49b40821)

    # Round 2
    a = GG(a, b, c, d, groups[1], S[1, 0], 0xf61e2562)
    d = GG(d, a, b, c, groups[6], S[1, 1], 0xc040b340)
    c = GG(c, d, a, b, groups[11], S[1, 2], 0x265e5a51)
    b = GG(b, c, d, a, groups[0], S[1, 3], 0xe9b6c7aa)

    a = GG(a, b, c, d, groups[5], S[1, 0], 0xd62f105d)
    d = GG(d, a, b, c, groups[10], S[1, 1], 0x2441453)
    c = GG(c, d, a, b, groups[15], S[1, 2], 0xd8a1e681)
    b = GG(b, c, d, a, groups[4], S[1, 3], 0xe7d3fbc8)

    a = GG(a, b, c, d, groups[9], S[1, 0], 0x21e1cde6)
    d = GG(d, a, b, c, groups[14], S[1, 1], 0xc33707d6)
    c = GG(c, d, a, b, groups[3], S[1, 2], 0xf4d50d87)
    b = GG(b, c, d, a, groups[8], S[1, 3], 0x455a14ed)

    a = GG(a, b, c, d, groups[13], S[1, 0], 0xa9e3e905)
    d = GG(d, a, b, c, groups[2], S[1, 1], 0xfcefa3f8)
    c = GG(c, d, a, b, groups[7], S[1, 2], 0x676f02d9)
    b = GG(b, c, d, a, groups[12], S[1, 3], 0x8d2a4c8a)

    # Round 3
    a = HH(a, b, c, d, groups[5], S[2, 0], 0xfffa3942)
    d = HH(d, a, b, c, groups[8], S[2, 1], 0x8771f681)
    c = HH(c, d, a, b, groups[11], S[2, 2], 0x6d9d6122)
    b = HH(b, c, d, a, groups[14], S[2, 3], 0xfde5380c)

    a = HH(a, b, c, d, groups[1], S[2, 0], 0xa4beea44)
    d = HH(d, a, b, c, groups[4], S[2, 1], 0x4bdecfa9)
    c = HH(c, d, a, b, groups[7], S[2, 2], 0xf6bb4b60)
    b = HH(b, c, d, a, groups[10], S[2, 3], 0xbebfbc70)

    a = HH(a, b, c, d, groups[13], S[2, 0], 0x289b7ec6)
    d = HH(d, a, b, c, groups[0], S[2, 1], 0xeaa127fa)
    c = HH(c, d, a, b, groups[3], S[2, 2], 0xd4ef3085)
    b = HH(b, c, d, a, groups[6], S[2, 3], 0x4881d05)

    a = HH(a, b, c, d, groups[9], S[2, 0], 0xd9d4d039)
    d = HH(d, a, b, c, groups[12], S[2, 1], 0xe6db99e5)
    c = HH(c, d, a, b, groups[15], S[2, 2], 0x1fa27cf8)
    b = HH(b, c, d, a, groups[2], S[2, 3], 0xc4ac5665)

    # Round 4
    a = II(a, b, c, d, groups[0], S[3, 0], 0xf4292244)
    d = II(d, a, b, c, groups[7], S[3, 1], 0x432aff97)
    c = II(c, d, a, b, groups[14], S[3, 2], 0xab9423a7)
    b = II(b, c, d, a, groups[5], S[3, 3], 0xfc93a039)

    a = II(a, b, c, d, groups[12], S[3, 0], 0x655b59c3)
    d = II(d, a, b, c, groups[3], S[3, 1], 0x8f0ccc92)
    c = II(c, d, a, b, groups[10], S[3, 2], 0xffeff47d)
    b = II(b, c, d, a, groups[1], S[3, 3], 0x85845dd1)

    a = II(a, b, c, d, groups[8], S[3, 0], 0x6fa87e4f)
    d = II(d, a, b, c, groups[15], S[3, 1], 0xfe2ce6e0)
    c = II(c, d, a, b, groups[6], S[3, 2], 0xa3014314)
    b = II(b, c, d, a, groups[13], S[3, 3], 0x4e0811a1)

    a = II(a, b, c, d, groups[4], S[3, 0], 0xf7537e82)
    d = II(d, a, b, c, groups[11], S[3, 1], 0xbd3af235)
    c = II(c, d, a, b, groups[2], S[3, 2], 0x2ad7d2bb)
    b = II(b, c, d, a, groups[9], S[3, 3], 0xeb86d391)

    result[0] += a
    result[1] += b
    result[2] += c
    result[3] += d
    result[0] &= 0xFFFFFFFF
    result[1] &= 0xFFFFFFFF
    result[2] &= 0xFFFFFFFF
    result[3] &= 0xFFFFFFFF


def generate_md5(input_text):
    """Generate MD5
    :param input_text: String
    :return: MD4 Hex
    """
    global result
    result = [A, B, C, D]

    input_bytes = input_text.encode()
    byte_len = len(input_bytes)
    group_count = byte_len // 64

    for i in range(group_count):
        groups = div_group(input_bytes, i * 64)
        trans(groups)

    rest = byte_len % 64
    tmp_bytes = list(range(64))
    if rest <= 56:
        for i in range(rest):
            tmp_bytes[i] = input_bytes[byte_len - rest + i]
        if rest < 56:
            tmp_bytes[rest] = 1 << 7
            for i in range(1, 56 - rest):
                tmp_bytes[rest + i] = 0

        tmp_len = byte_len << 3
        for i in range(8):
            tmp_bytes[56 + i] = tmp_len & 0xff
            tmp_len >>= 8
        groups = div_group(tmp_bytes, 0)
        trans(groups)
    else:
        for i in range(rest):
            tmp_bytes[i] = input_bytes[byte_len - rest + i]
        tmp_bytes[rest] = 1 << 7
        for i in range(rest + 1, 64):
            tmp_bytes[i] = 0
        groups = div_group(tmp_bytes, 0)
        trans(groups)

        for i in range(56):
            tmp_bytes[i] = 0

        tmp_len = byte_len << 3
        for i in range(8):
            tmp_bytes[56 + i] = tmp_len & 0xff
            tmp_len >>= 8
        groups = div_group(tmp_bytes, 0)
        trans(groups)

    return get_hash_hex_string()


def get_hash_hex_string():
    """Convert Hash value to Hex String
    :return: Hex String
    """
    result_string = ''
    for i in range(4):
        for j in range(4):
            tmp = result[i] & 0x0f
            str = convert_to_hex[tmp]
            result[i] >>= 4
            tmp = result[i] & 0x0f
            result_string += convert_to_hex[tmp] + str
            result[i] >>= 4

    return result_string


def div_group(input_bytes, index):
    """
    :param input_bytes: Int[]
    :param index: Int
    :return: Int
    """
    tmp = list(range(16))
    for i in range(16):
        tmp[i] = (eliminate_negative(input_bytes[4 * i + index]) |
                  (eliminate_negative(input_bytes[4 * i + index + 1])) << 8 |
                  (eliminate_negative(input_bytes[4 * i + index + 2])) << 16 |
                  (eliminate_negative(input_bytes[4 * i + index + 3])) << 24)
    return tmp


def eliminate_negative(b):
    """
    :param b: Int
    :return: Int
    """
    if b < 0:
        return b & 0x7F + 128
    else:
        return b


if __name__ == '__main__':
    print('md5(\'\') =', generate_md5(''))
    print('md5(\'a\') =', generate_md5('a'))
    print('md5(\'abc\') =', generate_md5('abc'))
    print('md5(\'message digest\') =', generate_md5('message digest'))
    print('md5(\'abcdefghijklmnopqrstuvwxyz\') =', generate_md5('abcdefghijklmnopqrstuvwxyz'))
    print('md5(\'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\') =',
          generate_md5('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'))
    print('md5(\'12345678901234567890123456789012345678901234567890123456789012345678901234567890\') =',
          generate_md5('12345678901234567890123456789012345678901234567890123456789012345678901234567890'))
