from random import randint
from math import ceil, floor, log
from WOTS import checksum, H
from time import time

def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

def get_random_32_bytes(index, leaf_number, some_bytes):
    return H(index.to_bytes(64, 'big') + leaf_number.to_bytes(64, 'big') + some_bytes)

def WOTS_plus_gen_secret_key(t, leaf_number, r_SEED):

    SK = []

    for i in range(t):
        x_i = get_random_32_bytes(i, leaf_number, r_SEED)
        SK += [x_i]
    return SK

def WOTS_plus_gen_public_key(t : list[int], w : list[int], leaf_number : int, r_SEED : bytes, SK : list[bytes]) -> tuple[list[bytes], list[bytes]]:
    
    PK = []

    for i in range(t):
        r_i = get_random_32_bytes(i, leaf_number, r_SEED)
        tmp = SK[i]
        
        for i in range(w - 1):
            tmp = H(byte_xor(tmp, r_i))
        PK += [tmp]
    
    return PK

def WOTS_plus_sign(M : str, w : int, t : int, SK : list[bytes], leaf_number : int, r_SEED : bytes) -> list[bytes]:

    w_length = ceil(log(w, 2))
    
    m = H(bytes(M, 'utf-8'))
    m = bin(int.from_bytes(m, byteorder = 'big'))[2:].zfill(l)

    M_w_nary = [m[i:i+w_length] for i in range(0, len(m), w_length)]
    M_w_nary[-1] = M_w_nary[-1] + ('0'*(w_length - len(M_w_nary[-1]))) # W ten sposób paddinguje wiadomość, aby ostatnio w - litera była pełna
    
    C = checksum(M_w_nary, w)
    M_C = [int(i, 2) for i in M_w_nary + C]

    sigma = []

    for i in range(t):
        
        r_i = H(i.to_bytes(64, 'big') + leaf_number.to_bytes(64, 'big') + r_SEED)

        tmp = SK[i]
        for j in range(M_C[i]):
            tmp = H(byte_xor(tmp, r_i))
        sigma += [tmp]
    
    return sigma

def WOTS_plus_verify(M : str, WOTS_plus_signature : list[bytes], w : int, t : int, PK : list[bytes], leaf_number : int, r_SEED : bytes) -> bool:

    w_length = ceil(log(w, 2))
    
    m = H(bytes(M, 'utf-8'))
    
    m = bin(int.from_bytes(m, byteorder ='big'))[2:].zfill(l)
    
    M_w_nary = [m[i:i+w_length] for i in range(0, len(m), w_length)]
    M_w_nary[-1] = M_w_nary[-1] + ('0'*(w_length - len(M_w_nary[-1]))) # W ten sposób paddinguje wiadomość, aby ostatnio w - litera była pełna
    
    C = checksum(M_w_nary, w)
    M_C = M_w_nary + C
    
    for i in range(t):
        
        r_i = H(i.to_bytes(64, 'big') + leaf_number.to_bytes(64, 'big') + r_SEED)
        tmp = WOTS_plus_signature[i]

        for j in range(w - 1 - int(M_C[i], 2)):
            tmp = H(byte_xor(tmp, r_i))
        if tmp != PK[i]:
            return False

    return True

def unit_test_WOTS_plus(M : str, w : int, master_key : bytes, leaf_number : int, r_SEED : bytes) -> bool:

    m = H(bytes(M, 'utf-8'))
    
    t_1 = ceil(l / log(w, 2))
    t_2 = floor(log(t_1*(w-1), 2) / log(w, 2))
    w_length = ceil(log(w, 2))
    
    t = t_1 + t_2
    SK = WOTS_plus_gen_secret_key(t, leaf_number, r_SEED)
    PK = WOTS_plus_gen_public_key(t, w, leaf_number, R_SEED, SK)

    sigma = WOTS_plus_sign(M, w, t, SK, leaf_number, R_SEED)
    verify = WOTS_plus_verify(M, sigma, w, t, PK, leaf_number, R_SEED)

    return verify

M = "Kryptografia kwantowa i postkwantowa 2022/2023 sierż. pchor. Mateusz Chudzik"
l = 256

if __name__ == "__main__":


    master_key = randint(2**256, (2**257) - 1)
    master_key = master_key.to_bytes(256, 'big') 
    
    R_SEED = randint(2**256, (2**257) - 1)
    R_SEED = H(R_SEED.to_bytes(256, 'big'))

    print("Wygenerowano master key oraz ziarno dla masek")

    print("Podaj wartosc w!")
    w = int(input())

    print("Podaj ile testow ma zostac wykonanych")

    tests_number = int(input())

    counter = 0
    start = time()
    for leaf_number in range(0, tests_number):
        test = unit_test_WOTS_plus(M, w, master_key, leaf_number, R_SEED)
        if test == True:
            counter += 1
    end = time()

    print("Liczba wykonanych testow", tests_number)
    print("Liczba zweryfikowanych podpisow", counter)
    print("Czas testowania ", end - start)

    unit_test_WOTS_plus(M, w, master_key, 0, R_SEED)
