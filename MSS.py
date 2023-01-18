from random import randint
from math import floor, ceil, log
from WOTS import WOTS_gen_keys, WOTS_sign, WOTS_verify, H
from time import time

def MSS_gen_WOTS_keys(h : int, t : list[int], w : list[int], l : int, master_key : bytes) -> tuple[list[list[bytes]], list[list[int]]]:
    
    WOTS_SK = []
    WOTS_PK = []

    for i in range(2**h):
        WOTS_sk, WOTS_pk = WOTS_gen_keys(t, w, l, master_key, i)
        WOTS_PK += [WOTS_pk]
        WOTS_SK += [WOTS_sk]

    return WOTS_SK, WOTS_PK


def MSS_get_Merkle_Tree(h : int, t: int, w : int, WOTS_PK : list[bytes], master_key : bytes) -> list[bytes]:

    WOTS_PK = []
    WOTS_SK = []
    leaves = []
    WOTS_SK, WOTS_PK = MSS_gen_WOTS_keys(h, t, w, l, master_key)

    for i in range(2**h):
        WOTS_pk = WOTS_PK[i]
        leaves += [H(b"".join(WOTS_pk))]

    Tree = leaves

    for i in range(1, h + 1):
        level_size = 2**(h - i)
        level = []
        for j in range(level_size):
            level += [H(Tree[2*j] + Tree[2*j + 1])]
        Tree = level + Tree 

    return Tree

def MSS_get_path_indexes(s : int, h : int) -> list[int]:

    v_h = []
    s_i = s + (2**h) - 1

    for i in range(0, h):
        if s_i % 2 == 0:
            v_h += [s_i - 1]
            s_i = (s_i // 2) - 1
        else:
            v_h += [s_i + 1]
            s_i = s_i // 2

    return v_h
    
def MSS_get_path(s : int, h : int) -> list[int]:

    v_h = []
    s_i = s + (2**h) - 1

    global MSS_Tree

    for i in range(0, h):
        if s_i % 2 == 0:
            v_h += [MSS_Tree[s_i - 1]]
            s_i = (s_i // 2) - 1
        else:
            v_h += [MSS_Tree[s_i + 1]]
            s_i = s_i // 2

    return v_h


def MSS_sign(M : str, WOTS_SK : list[bytes], h : int, t : int, w : int, l : int, master_key : bytes, s : int) -> tuple[int, list[bytes], list[bytes], list[int]]:
    
    m = H(bytes(M, 'utf-8'))

    SK_s, PK_s = WOTS_gen_keys(t, w, l, master_key, s)

    sigma = WOTS_sign(M, w, t, WOTS_SK[s])
    path = MSS_get_path(s, h)

    return s, sigma, PK_s, path



def MSS_verify(M : str, sigma_MSS : tuple[int, list[bytes], list[bytes], list[int]], root : bytes, tree : list[bytes]) -> bool:

    s, sigma, PK_s, path = sigma_MSS
    indexes = MSS_get_path_indexes(s, h)

    verify_WOTS_sign = WOTS_verify(M, w, t, sigma, PK_s)

    if verify_WOTS_sign != True:
        return False
    
    PK = b"".join(PK_s)
    leaf = H(PK)

    temp = leaf
    for i in range(len(indexes)):
        if indexes[i] % 2 == 0:
            temp = H(temp + path[i])
        else:
            temp = H(path[i] + temp)
    
    if temp == root:
        return True
    else:
        return False


l = 256
M = "Kryptografia kwantowa i postkwantowa 2022/2023 sierż. pchor. Mateusz Chudzik"

if __name__ == "__main__":   

    print("Uruchomiono skrypt do testow MSS'a")
    print("Podaj wybrana wysokosc drzewa!")
    h = int(input())

    print("Podaj wartosc w!")
    w = int(input())
    
    t_1 = ceil(l / log(w, 2))
    t_2 = floor(log(t_1*(w-1), 2) / log(w, 2))
    w_length = ceil(log(w, 2))
    t = t_1 + t_2

    master_key = randint(2**256, (2**257) - 1)
    master_key = master_key.to_bytes(256, 'big')
    print("Wygenerowano master key")

    start = time()
    WOTS_SK, WOTS_PK = MSS_gen_WOTS_keys(h, t, w, l, master_key)
    MSS_Tree = MSS_get_Merkle_Tree(h, t, w, WOTS_PK, master_key)
    root = MSS_Tree[0]
    end = time()

    print("Wygenerowano drzewo. Generacja drzewa trwala "+ str(end - start)+ " s")

    counter = 0
    start = time()
    for s in range(2**h):
        sigma_MSS = MSS_sign(M, WOTS_SK, h, t, w, l, master_key, s)
        verify_MSS = MSS_verify(M, sigma_MSS, root, MSS_Tree)

        if verify_MSS == True:
            counter += 1
    end = time()

    print("Liczba testow zweryfikowanych pozytywnie ", counter)
    print("Liczba wykonanych testow", 2**h)
    print("Zajelo to:", end - start)
