from hashlib import sha256
from random import randint
from math import ceil, floor, log
from time import time

def H(x):
    l = 256
    h = sha256()
    h.update(x)
    return h.digest()[0:l]

def checksum(M_w_nary : list[int], w : int) -> list[str]:
    w_length = ceil(log(w, 2))

    C = 0
    
    for b_i in M_w_nary:
        C += w - 1 - int(b_i, 2)
    
    C_bin = bin(C)[2:]
    
    C_w_nary = [C_bin[i:i+w_length] for i in range(0, len(C_bin), w_length)]
    C_w_nary[-1] = C_w_nary[-1] + ('0'*(w_length - len(C_w_nary[-1])))
    
    return C_w_nary
    
def WOTS_gen_keys(t : list[int], w : list[int], l : int, master_key : bytes, leaf_number : int) -> tuple[list[bytes], list[bytes]]:
    
    SK = []
    PK = []
    for i in range(t):
        x_i = H(i.to_bytes(64, 'big') + leaf_number.to_bytes(64, 'big') + master_key)
        SK += [x_i]
        
        tmp = x_i
        
        for i in range(w - 1):
            tmp = H(tmp)
        PK += [tmp]
    
    return SK, PK

def WOTS_sign(M : str, w : int, t : int, SK : list[bytes]) -> list[bytes]:
    
    w_length = ceil(log(w, 2))
    
    m = H(bytes(M, 'utf-8'))
    m = bin(int.from_bytes(m, byteorder = 'big'))[2:].zfill(l)
    
    M_w_nary = [m[i:i+w_length] for i in range(0, len(m), w_length)]
    M_w_nary[-1] = M_w_nary[-1] + ('0'*(w_length - len(M_w_nary[-1]))) # W ten sposób paddinguje wiadomość, aby ostatnio w - litera była pełna
    
    C = checksum(M_w_nary, w)
    M_C = [int(i, 2) for i in M_w_nary + C]
    
    sigma = []
    
    for i in range(t):
        tmp = SK[i]
        for j in range(M_C[i]):
            tmp = H(tmp)
        sigma += [tmp]
        
    return sigma
        

def WOTS_verify(M : str, w : int, t : int, sigma : list[bytes], PK : list[bytes]) -> bool:
    
    w_length = ceil(log(w, 2))
    
    m = H(bytes(M, 'utf-8'))
    
    m = bin(int.from_bytes(m, byteorder ='big'))[2:].zfill(l)
    
    M_w_nary = [m[i:i+w_length] for i in range(0, len(m), w_length)]
    M_w_nary[-1] = M_w_nary[-1] + ('0'*(w_length - len(M_w_nary[-1]))) # W ten sposób paddinguje wiadomość, aby ostatnio w - litera była pełna
    
    C = checksum(M_w_nary, w)
    M_C = M_w_nary + C
    
    counter = 0
    
    for i in range(t):
        tmp = sigma[i]
        for j in range(w - 1 - int(M_C[i], 2)):
            tmp = H(tmp)
        if tmp == PK[i]:
            counter += 1

    return counter == t

def unit_test_WOTS(M : str, w : int, master_key : bytes, leaf_number : int) -> bool:
    m = H(bytes(M, 'utf-8'))
    
    t_1 = ceil(l / log(w, 2))
    t_2 = floor(log(t_1*(w-1), 2) / log(w, 2))
    w_length = ceil(log(w, 2))
    
    t = t_1 + t_2
    

    SK, PK = WOTS_gen_keys(t, w, l, master_key, leaf_number)

    sigma = WOTS_sign(M, w, t, SK)
    V = WOTS_verify(M, w, t, sigma, PK)

    return V
    
l = 256
M = "Kryptografia kwantowa i postkwantowa 2022/2023 sierz. pchor. Mateusz Chudzik"


if __name__ == "__main__":    
    
    print("Uruchomiono skrypt do testów WOTS'a")

    master_key = randint(2**256, (2**257) - 1)
    master_key = master_key.to_bytes(256, 'big') 

    print("Wygenerowano master key oraz ziarno dla masek")

    print("Podaj wartosc w!")
    w = int(input())

    print("Podaj ile testow ma zostac wykonanych")

    tests_number = int(input())

    counter = 0
    start = time()
    for leaf_number in range(0, tests_number):
        test = unit_test_WOTS(M, w, master_key, leaf_number)
        if test == True:
            counter += 1
    end = time()

    print("Liczba wykonanych testow", tests_number)
    print("Liczba zweryfikowanych podpisow", counter)
    print("Czas testowania ", end - start)