

if __name__ == "__main__":
    
    print("Algorytmy do testowania:")

    print("\t [1] - WOTS")
    print("\t [2] - WOTS+")
    print("\t [3] - MSS")
    print("\t [4] - XMSS")
    
    choice = input()

    if choice == '1':
        exec(open("WOTS.py").read())
    elif choice == '2':
        exec(open("WOTS_plus.py").read())
    elif choice == '3':
        exec(open("MSS.py").read())
    elif choice == '4':
        exec(open("XMSS.py").read())
    else:
        print("Podano nieprawidłowy argument")