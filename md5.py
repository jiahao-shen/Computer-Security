"""
@project: Computer-Security
@author: sam
@file md5.py
@ide: PyCharm
@time: 2018-12-24 16:57:28
@blog: https://jiahaoplus.com
"""
# Initialization Constants
import math

A = 0x67452301
B = 0xefcdab89
C = 0x98badcfe
D = 0x10325476

S = [[7, 12, 17, 22],
     [5, 9, 14, 20],
     [4, 11, 16, 23],
     [6, 10, 15, 21]]

# [abs(sin(x)) * (2 ^ 32)]
t = [int(hex(math.floor(abs(math.sin(i + 1)) * (2 ** 32))), 16) for i in range(64)]

result = [A, B, C, D]

convert_to_hex = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f']


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
    a += (F(b, c, d) & 0xffffffff) + x + ac
    a = ((a & 0xffffffff) << s | (a & 0xffffffff) >> (32 - s))
    a += b
    return a & 0xffffffff


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
    a += (G(b, c, d) & 0xffffffff) + x + ac
    a = ((a & 0xffffffff) << s | (a & 0xffffffff) >> (32 - s))
    a += b
    return a & 0xffffffff


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
    a += (H(b, c, d) & 0xffffffff) + x + ac
    a = ((a & 0xffffffff) << s | (a & 0xffffffff) >> (32 - s))
    a += b
    return a & 0xffffffff


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
    a += (I(b, c, d) & 0xffffffff) + x + ac
    a = ((a & 0xffffffff) << s | (a & 0xffffffff) >> (32 - s))
    a += b
    return a & 0xffffffff


def trans(groups):
    """
    :param groups: Int[]
    :return:
    """
    a, b, c, d = result
    # Round 1
    a = FF(a, b, c, d, groups[0], S[0][0], t[0])
    d = FF(d, a, b, c, groups[1], S[0][1], t[1])
    c = FF(c, d, a, b, groups[2], S[0][2], t[2])
    b = FF(b, c, d, a, groups[3], S[0][3], t[3])

    a = FF(a, b, c, d, groups[4], S[0][0], t[4])
    d = FF(d, a, b, c, groups[5], S[0][1], t[5])
    c = FF(c, d, a, b, groups[6], S[0][2], t[6])
    b = FF(b, c, d, a, groups[7], S[0][3], t[7])

    a = FF(a, b, c, d, groups[8], S[0][0], t[8])
    d = FF(d, a, b, c, groups[9], S[0][1], t[9])
    c = FF(c, d, a, b, groups[10], S[0][2], t[10])
    b = FF(b, c, d, a, groups[11], S[0][3], t[11])

    a = FF(a, b, c, d, groups[12], S[0][0], t[12])
    d = FF(d, a, b, c, groups[13], S[0][1], t[13])
    c = FF(c, d, a, b, groups[14], S[0][2], t[14])
    b = FF(b, c, d, a, groups[15], S[0][3], t[15])

    # Round 2
    a = GG(a, b, c, d, groups[1], S[1][0], t[16])
    d = GG(d, a, b, c, groups[6], S[1][1], t[17])
    c = GG(c, d, a, b, groups[11], S[1][2], t[18])
    b = GG(b, c, d, a, groups[0], S[1][3], t[19])

    a = GG(a, b, c, d, groups[5], S[1][0], t[20])
    d = GG(d, a, b, c, groups[10], S[1][1], t[21])
    c = GG(c, d, a, b, groups[15], S[1][2], t[22])
    b = GG(b, c, d, a, groups[4], S[1][3], t[23])

    a = GG(a, b, c, d, groups[9], S[1][0], t[24])
    d = GG(d, a, b, c, groups[14], S[1][1], t[25])
    c = GG(c, d, a, b, groups[3], S[1][2], t[26])
    b = GG(b, c, d, a, groups[8], S[1][3], t[27])

    a = GG(a, b, c, d, groups[13], S[1][0], t[28])
    d = GG(d, a, b, c, groups[2], S[1][1], t[29])
    c = GG(c, d, a, b, groups[7], S[1][2], t[30])
    b = GG(b, c, d, a, groups[12], S[1][3], t[31])

    # Round 3
    a = HH(a, b, c, d, groups[5], S[2][0], t[32])
    d = HH(d, a, b, c, groups[8], S[2][1], t[33])
    c = HH(c, d, a, b, groups[11], S[2][2], t[34])
    b = HH(b, c, d, a, groups[14], S[2][3], t[35])

    a = HH(a, b, c, d, groups[1], S[2][0], t[36])
    d = HH(d, a, b, c, groups[4], S[2][1], t[37])
    c = HH(c, d, a, b, groups[7], S[2][2], t[38])
    b = HH(b, c, d, a, groups[10], S[2][3], t[39])

    a = HH(a, b, c, d, groups[13], S[2][0], t[40])
    d = HH(d, a, b, c, groups[0], S[2][1], t[41])
    c = HH(c, d, a, b, groups[3], S[2][2], t[42])
    b = HH(b, c, d, a, groups[6], S[2][3], t[43])

    a = HH(a, b, c, d, groups[9], S[2][0], t[44])
    d = HH(d, a, b, c, groups[12], S[2][1], t[45])
    c = HH(c, d, a, b, groups[15], S[2][2], t[46])
    b = HH(b, c, d, a, groups[2], S[2][3], t[47])

    # Round 4
    a = II(a, b, c, d, groups[0], S[3][0], t[48])
    d = II(d, a, b, c, groups[7], S[3][1], t[49])
    c = II(c, d, a, b, groups[14], S[3][2], t[50])
    b = II(b, c, d, a, groups[5], S[3][3], t[51])

    a = II(a, b, c, d, groups[12], S[3][0], t[52])
    d = II(d, a, b, c, groups[3], S[3][1], t[53])
    c = II(c, d, a, b, groups[10], S[3][2], t[54])
    b = II(b, c, d, a, groups[1], S[3][3], t[55])

    a = II(a, b, c, d, groups[8], S[3][0], t[56])
    d = II(d, a, b, c, groups[15], S[3][1], t[57])
    c = II(c, d, a, b, groups[6], S[3][2], t[58])
    b = II(b, c, d, a, groups[13], S[3][3], t[59])

    a = II(a, b, c, d, groups[4], S[3][0], t[60])
    d = II(d, a, b, c, groups[11], S[3][1], t[61])
    c = II(c, d, a, b, groups[2], S[3][2], t[62])
    b = II(b, c, d, a, groups[9], S[3][3], t[63])

    result[0] += a
    result[1] += b
    result[2] += c
    result[3] += d
    result[0] &= 0xffffffff
    result[1] &= 0xffffffff
    result[2] &= 0xffffffff
    result[3] &= 0xffffffff


def generate_md5(input_text):
    """Generate MD5
    :param input_text: String
    :return: MD4 Hex
    """
    global result
    result = [A, B, C, D]  # Initialize result

    input_bytes = input_text.encode()  # Transform String to bytes
    byte_len = len(input_bytes)  # Get length
    group_count = byte_len // 64  # Get number of groups, each group 512bits(64 bytes)

    for i in range(group_count):
        groups = div_group(input_bytes, i * 64)
        trans(groups)  # Handle each group

    rest = byte_len % 64  # Get the rest message
    tmp_bytes = list(range(64))
    if rest <= 56:  # If rest <= 448bits(56 bytes)
        for i in range(rest):
            tmp_bytes[i] = input_bytes[byte_len - rest + i]  # Copy the rest bits
        if rest < 56:  # If rest < 56
            tmp_bytes[rest] = 1 << 7  # Append 10000000
            for i in range(1, 56 - rest):  # The rest append zero
                tmp_bytes[rest + i] = 0

        # Append the length of message
        tmp_len = byte_len << 3
        for i in range(8):
            tmp_bytes[56 + i] = tmp_len & 0xff
            tmp_len >>= 8

        # Handle the rest
        groups = div_group(tmp_bytes, 0)
        trans(groups)
    else:
        # If rest > 448bits(56 bytes)
        for i in range(rest):
            tmp_bytes[i] = input_bytes[byte_len - rest + i]  # Copy the rest bits
        tmp_bytes[rest] = 1 << 7  # Append 10000000
        for i in range(rest + 1, 64):  # The rest append zero
            tmp_bytes[i] = 0
        # Handle the first rest
        groups = div_group(tmp_bytes, 0)
        trans(groups)

        for i in range(56):  # Continue appending zero
            tmp_bytes[i] = 0

        # Append the length of message
        tmp_len = byte_len << 3
        for i in range(8):
            tmp_bytes[56 + i] = tmp_len & 0xff
            tmp_len >>= 8

        # Handle the rest
        groups = div_group(tmp_bytes, 0)
        trans(groups)

    return get_hash_hex_string()


def get_hash_hex_string():
    """Convert Hash value to Hex String
    :return: Hex String
    """
    result_string = ''
    for i in range(4):
        # For each 32bits group, get 8 hex characters
        for j in range(4):
            tmp = result[i] & 0x0f  # Get the last 4bits
            str = convert_to_hex[tmp]  # Convert to hex
            result[i] >>= 4  # Get the next last 4bits
            tmp = result[i] & 0x0f  # Convert to hex
            result_string += convert_to_hex[tmp] + str  # Append to result_string
            result[i] >>= 4  # Get the next last bits

    return result_string


def div_group(input_bytes, index):
    """
    :param input_bytes: Int[]
    :param index: Int
    :return: Int
    """
    # Divide each 512bits(64 bytes) group to 16 smaller groups
    # Each smaller groups has 32bits(4 bytes)
    tmp = list(range(16))
    for i in range(16):
        tmp[i] = (eliminate_negative(input_bytes[4 * i + index]) |
                  (eliminate_negative(input_bytes[4 * i + index + 1])) << 8 |
                  (eliminate_negative(input_bytes[4 * i + index + 2])) << 16 |
                  (eliminate_negative(input_bytes[4 * i + index + 3])) << 24)
    return tmp


def eliminate_negative(b):
    """Eliminate the negative symbol
    :param b: Int
    :return: Int
    """
    if b < 0:
        return b & 0x7F + 128
    else:
        return b


if __name__ == '__main__':
    # d41d8cd98f00b204e9800998ecf8427e
    print('md5(\'\') =', generate_md5(''))
    # 0cc175b9c0f1b6a831c399e269772661
    print('md5(\'a\') =', generate_md5('a'))
    # 900150983cd24fb0d6963f7d28e17f72
    print('md5(\'abc\') =', generate_md5('abc'))
    # f96b697d7cb7938d525a2f31aaf161d0
    print('md5(\'message digest\') =', generate_md5('message digest'))
    # c3fcd3d76192e4007dfb496cca67e13b
    print('md5(\'abcdefghijklmnopqrstuvwxyz\') =', generate_md5('abcdefghijklmnopqrstuvwxyz'))
    # d174ab98d277d9f5a5611c2c9f419d9f
    print('md5(\'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\') =',
          generate_md5('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'))
    # 57edf4a22be3c955ac49da2e2107b67a
    print('md5(\'12345678901234567890123456789012345678901234567890123456789012345678901234567890\') =',
          generate_md5('12345678901234567890123456789012345678901234567890123456789012345678901234567890'))
