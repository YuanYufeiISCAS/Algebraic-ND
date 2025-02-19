import numpy as np

from speck import *
import array

def output_data(n, nr, diff=(0x0040, 0x0000)):
    # 0010, 2000 for 6 rounds acc
    # 2800, 0010 for 8 rounds acc 0.513
    # a840, 0010 for 9 rounds acc 0.5015
    keys = np.frombuffer(urandom(8 * n), dtype=np.uint16).reshape(4, -1)
    plain0l = np.frombuffer(urandom(2 * n), dtype=np.uint16)
    plain0r = np.frombuffer(urandom(2 * n), dtype=np.uint16)
    plain1l = plain0l ^ diff[0]
    plain1r = plain0r ^ diff[1]
    ks = expand_key(keys, nr)
    ctdata0l, ctdata0r = encrypt((plain0l, plain0r), ks)
    ctdata1l, ctdata1r = encrypt((plain1l, plain1r), ks)
    X = ((ctdata0l.astype(np.uint32) ^ ctdata1l.astype(np.uint32)) << 16) ^ (ctdata1r.astype(np.uint32) ^ ctdata0r.astype(np.uint32))
    # X = convert_to_binary([ctdata0l, ctdata0r, ctdata1l, ctdata1r])
    # X = convert_to_binary_2([ctdata0l, ctdata1l, ctdata0r, ctdata1r])
    return X

def output_random(n, nr):
    keys = np.frombuffer(urandom(8 * n), dtype=np.uint16).reshape(4, -1)
    plain0l = np.frombuffer(urandom(2 * n), dtype=np.uint16)
    plain0r = np.frombuffer(urandom(2 * n), dtype=np.uint16)
    plain1l = np.frombuffer(urandom(2 * n), dtype=np.uint16)
    plain1r = np.frombuffer(urandom(2 * n), dtype=np.uint16)
    ks = expand_key(keys, nr)
    ctdata0l, ctdata0r = encrypt((plain0l, plain0r), ks)
    ctdata1l, ctdata1r = encrypt((plain1l, plain1r), ks)
    # X = convert_to_binary([ctdata0l, ctdata0r, ctdata1l, ctdata1r])
    # X = convert_to_binary_2([ctdata0l, ctdata1l, ctdata0r, ctdata1r])
    X = ((ctdata0l.astype(np.uint32) ^ ctdata1l.astype(np.uint32)) << 16) ^ (ctdata1r.astype(np.uint32) ^ ctdata0r.astype(np.uint32))
    return X

def test_output():
    keys = np.frombuffer(urandom(8 * 2), dtype=np.uint16).reshape(4, -1)
    plain0l = np.frombuffer(urandom(2 * 2), dtype=np.uint16)
    plain0r = np.frombuffer(urandom(2 * 2), dtype=np.uint16)
    X0 = (plain0l.astype(np.uint32) << 16) ^ (plain0r.astype(np.uint32))
    plain1l = plain0l ^ 0x0040
    plain1r = plain0r
    X1 = (plain0l.astype(np.uint32) << 16) ^ (plain0r.astype(np.uint32))

    ks = expand_key(keys, 7)
    ctdata0l, ctdata0r = encrypt((plain0l, plain0r), ks)
    ctdata1l, ctdata1r = encrypt((plain1l, plain1r), ks)
    print(np.binary_repr(ctdata1r[0], width=32))
    Y0 = (ctdata0l.astype(np.uint32) << 16) ^ (ctdata0r.astype(np.uint32))
    Y1 = (ctdata1l.astype(np.uint32) << 16) ^ (ctdata1r.astype(np.uint32))
    dY = ((ctdata0l.astype(np.uint32) ^ ctdata1l.astype(np.uint32)) << 16) ^ (ctdata1r.astype(np.uint32) ^ ctdata0r.astype(np.uint32))

    bin_y0 = np.binary_repr(Y0[0], width=32)
    bin_y1 = np.binary_repr(Y1[0], width=32)
    bin_dy = np.binary_repr(dY[0], width=32)
    print(bin_y0)
    print(bin_y1)
    print(bin_dy)



if __name__ == '__main__':
    test_output()