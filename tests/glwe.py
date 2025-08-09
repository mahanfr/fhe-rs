# https://www.zama.ai/post/tfhe-deep-dive-part-1
import numpy as np

Q = 4093
P = 4
N = 8
Delta = Q // P
K = 1


def sample_uniform():
    return np.random.randint(0, 2, size=N)


def poly_mul(a, b):
    # naive negacyclic modulo x^N + 1
    res = np.zeros(N, dtype=int)
    for i in range(N):
        for j in range(N):
            k = (i + j) % N
            coef = a[i] * b[j]
            if i + j >= N:
                coef = -coef
            res[k] = (res[k] + coef) % Q
    return res


s = sample_uniform()
m = np.array([1, 0, 1, 0, 1, 1, 1, 0])
print("m =", m)
a = np.random.randint(-Q/2, Q/2, size=N)
print("a =", a)
e = sample_uniform()
print("e =", e)

delataM = np.array(m * (Delta))
print("DelatM = ", delataM)
b = (poly_mul(a, s) + delataM + e) % Q
print("b =", b)

delataMWithE = b - (poly_mul(a, s)) % Q
decode = np.round(delataMWithE / Delta).astype(int) % P
print("result =", decode)
