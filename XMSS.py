from random import randint
from math import ceil, floor, log
from WOTS import H
from WOTS_plus import WOTS_plus_gen_secret_key, WOTS_plus_gen_public_key, WOTS_plus_sign, WOTS_plus_verify, byte_xor
from time import time



def get_L_tree_root(PK : list[bytes], leaf_number : int, R_SEED : bytes, t : int) -> bytes:
    t_prim = t
    h = 1
    l = PK

    while t_prim > 1:

        for i in range(0, floor(t_prim / 2) - 1):
            r_i_L = H(i.to_bytes(64, 'big') + leaf_number.to_bytes(64, 'big') + R_SEED)
            r_i_R = H((2*i + 1).to_bytes(64, 'big') + leaf_number.to_bytes(64, 'big') + R_SEED)

            l[i] = H(byte_xor(l[2*i], r_i_L) + byte_xor(l[2*i + 1], r_i_R))
        if t_prim % 2 == 1:
            l[floor(t_prim / 2)] = l[t_prim - 1]
        t_prim = ceil(t_prim / 2)
        h += 1

    return l[0]

def get_XMSS_Tree(h : int, t : int, w : int, R_SEED : bytes):
    leaves = []

    for s in range(2**h):
        sk = WOTS_plus_gen_secret_key(t, s, R_SEED)
        pk = WOTS_plus_gen_public_key(t, w, s, R_SEED, sk)
    
        XMSS_node = get_L_tree_root(pk, s, R_SEED, t)
        leaves += [XMSS_node]

    Tree = leaves

    for i in range(1, h + 1):
        level_size = 2**(h - i)
        level = []
        for j in range(level_size):
            
            r_i_L = H(i.to_bytes(64, 'big') + (2*j).to_bytes(64, 'big') + R_SEED)
            r_i_R = H(i.to_bytes(64, 'big') + (2*j + 1).to_bytes(64, 'big') + R_SEED)

            level += [H(byte_xor(Tree[2*j], r_i_L) + byte_xor(Tree[2*j + 1], r_i_R))]
        Tree = level + Tree
    return Tree

def XMSS_get_path_indexes(s : int, h : int) -> list[int]:

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

def XMSS_get_path(s : int, h : int, XMSS_Tree : list[bytes]) -> list[bytes]:

    v_hash = []
    indexes = XMSS_get_path_indexes(s, h)

    for i in indexes:
        v_hash += [XMSS_Tree[i]]
    
    return v_hash

def XMSS_sign(M : str, WOTS_plus_SK : list[bytes], h : int, t : int, w : int, l : int, R_SEED : bytes, s : int, XMSS_TREE : list[bytes]) -> list[bytes]:

    sigma = WOTS_plus_sign(M, w, t, WOTS_plus_SK, s, R_SEED)
    path = XMSS_get_path(s, h, XMSS_TREE)

    return s, R_SEED, sigma, path

def XMSS_verify(M : str, XMSS_signature : tuple, WOTS_plus_PK : list[bytes], h : int, t : int, w : int, root : bytes) -> bool:

    s, R_SEED, WOTS_sigma, path = XMSS_signature
    verify_WOTS_plus = WOTS_plus_verify(M, WOTS_sigma, w, t, WOTS_plus_PK, s, R_SEED)

    if verify_WOTS_plus != True:
        return False

    indexes = XMSS_get_path_indexes(s, h)
    L_tree_root = get_L_tree_root(WOTS_plus_PK, s, R_SEED, t)

    temp = L_tree_root
    for i in range(len(indexes)):
        index = indexes[i] - (2**(h - i) - 1)
        r_i_L = 0
        r_i_R = 0
        if index % 2 == 0:
            r_i_L = H((i+1).to_bytes(64, 'big') + (index).to_bytes(64, 'big') + R_SEED)
            r_i_R = H((i+1).to_bytes(64, 'big') + (index + 1).to_bytes(64, 'big') + R_SEED)
            temp = H(byte_xor(path[i], r_i_L) + byte_xor(temp, r_i_R))
        else:
            r_i_L = H((i+1).to_bytes(64, 'big') + (index - 1).to_bytes(64, 'big') + R_SEED)
            r_i_R = H((i+1).to_bytes(64, 'big') + (index).to_bytes(64, 'big') + R_SEED)
            temp = H(byte_xor(temp, r_i_L) + byte_xor(path[i], r_i_R))
    return root == temp

M = "Kryptografia kwantowa i postkwantowa 2022/2023 sierż. pchor. Mateusz Chudzik"
l = 256


if __name__ == "__main__":


    print("Podaj wartosc w!")
    w = int(input())

    print("Podaj wysokosc drzewa!")
    h = int(input())
    
    master_key = randint(2**256, (2**257) - 1)
    master_key = master_key.to_bytes(256, 'big') 
    
    R_SEED = randint(2**256, (2**257) - 1)
    R_SEED = H(R_SEED.to_bytes(256, 'big'))
    print("Wygenerowano master key i ziarno dla masek")

    t_1 = ceil(l / log(w, 2))
    t_2 = floor(log(t_1*(w-1), 2) / log(w, 2))
    t = t_1 + t_2
    w_length = ceil(log(w, 2))

    start = time()
    XMSS_Tree = get_XMSS_Tree(h, t, w, R_SEED)
    root = XMSS_Tree[0]
    end = time()

    print("Drzewo zostalo wygenerowane. Generacja drzewa trwala "+ str(end - start)+ " s")

    counter = 0
    start = time()
    for s in range(2**h):
        sk = WOTS_plus_gen_secret_key(t, s, R_SEED)
        pk = WOTS_plus_gen_public_key(t, w, s, R_SEED, sk)
        XMSS_sigma = XMSS_sign(M, sk, h, t, w, l, R_SEED, s, XMSS_Tree)
        verify_XMSS = XMSS_verify(M, XMSS_sigma, pk, h, t, w, root)
        
        if verify_XMSS == True:
            counter += 1
    end = time()

    print("Liczba testow zweryfikowanych pozytywnie ", counter)
    print("Liczba wykonanych testow", 2**h)
    print("Zajelo to:", end - start)