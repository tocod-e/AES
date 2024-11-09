import galois
#from numpy.lib.polynomial import poly
print("Aufgabe(1) Schlüsselfahrplan in AES\n")

sbox = open("c:/Users/moham/OneDrive - Hochschule Albstadt-Sigmaringen/HS Albsig/Semester 4/Betriebssicherheit/Praktikum/New folder/AES/sbox", "r").read().split(" ")

def g_fun(x: list, round: int) -> list:
    if len(x) != 4:
        raise("x not 4 byte lenght")
    

    #sbox = open("sbox", "r").read().split(" ")
    carry = x[0]
    x = x[1:]
    x.append(carry)
    result = list()
    for i in range(4):
        byte = x[i]
        lowNibble = byte & 0x0F
        highNibble = byte >> 4
        byte = int(sbox[highNibble * 16 + lowNibble], 16)
        if i == 0:
            gal2_8 = galois.Poly.Degrees([8, 4, 3, 1, 0], [1, 1, 1, 1, 1], galois.GF(2**8))
            polX = galois.Poly.Degrees([round], field=galois.GF(2**8))
            polres = polX % gal2_8
            byte ^= sum([int(polres.coeffs[x])*2 **(len(polres.coeffs) - x - 1) for x in range(len(polres.coeffs))])
        result.append(byte)
    return result

x = [0xcd, 0x9a, 0x27, 0xc8]
print("Aufgabe 1(B): \nErgebnis der ersten Runde für g(x)\ng(x,0) = " + str([hex(byte) for byte in g_fun(x, 0)]) + "\n")

def genRoundKeys(key: list) -> list:
    keys = [key]
    for round in range(10):
        xor = g_fun(keys[-1][3], round)
        newKey = []
        for i in range(4):
            newKey.append([xor[j] if i == 0 else keys[-1][i][j] ^ newKey[i-1][j] for j in range(4)])
        keys.append(newKey)
    
    # Rundenschlüssel in flache Listen umwandeln
    flat_keys = []
    for round_key in keys:
        flat_keys.append([byte for word in round_key for byte in word])
    return flat_keys


key = [[0x7d, 0x37, 0x36, 0x5e],
       [0x1d, 0x25, 0x70, 0x3d],
       [0xbd, 0x5b, 0x23, 0xcd],
       [0xe5, 0xa1, 0xae, 0x5e]]
roundkeys = genRoundKeys(key)
for row in range(4):
    print("\t".join([hex(roundkeys[-1][row * 4 + column]) for column in range(4)]))
print()


key_n_1 = [[0x06, 0x6d, 0xb5, 0xb0], [0x32, 0x20, 0x95, 0xb7],
       [0x2f, 0xe3, 0x80, 0x4b], [0xb6, 0xef, 0xbd, 0x83]]

key_n = "c21759fef037cc49dfd44c02693bf181"
results = []
testkey = key.copy()
for round in range(1, 10):
    xor = g_fun(key_n_1[3], round)
    newKey = []
    for i in range(4):
        newKey.append([xor[j] if i == 0 else key_n_1[i][j] ^ newKey[i-1][j] for j in range(4)])
    roundkey = "".join(["{:02x}".format(byte) for word in newKey for byte in word])
    if key_n == roundkey:
        print("Aufgabe 1(D): \nMatch at round: " + str(round))
        break

k = [[0xcd, 0x7d, 0x37, 0x36],
       [0x9a, 0x1d, 0x25, 0x70],
       [0x27, 0xbd, 0x5b, 0x23],
       [0xc8, 0xe5, 0xa1, 0xae]]

roundkeys = genRoundKeys(k)
# Korrektur der Schleife zur Erzeugung von k0_und_k1
k0_und_k1 = "".join([hex(byte) for word in roundkeys[:2] for byte in word])

print("Aufgabe 2(A): \nSchlüssel k0 und k1 = ", k0_und_k1, "\n")



GF256 = galois.GF(2**8, irreducible_poly="x^8 + x^4 + x^3 + x + 1")
# Prepare Mix-Columns constants
GF1 = GF256(1)
GF2 = GF256(2)
GF3 = GF256(3)
MixedColumnTable = [[GF2, GF3, GF1, GF1],
                    [GF1, GF2, GF3, GF1],
                    [GF1, GF1, GF2, GF3],
                    [GF3, GF1, GF1, GF2]]
print("Aufgabe(2) Erste Runde in AES\n")


class AES:
    def __init__(self, k, x):
        self.k = k
        self.x = x
        self.sboxes = sbox
        self.roundkeys = genRoundKeys(k)

    def out(self, x: list) -> str:
        return "\n".join([str([hex(byte) for byte in l]) for l in x])

    
    def key_whitening(self):
        for column in range(4):
            for element in range(4):
                self.x[column][element] ^= self.roundkeys[0][column * 4 + element]
        return self.x

    
    def byte_substitution(self):
        for column in range(4):
            for element in range(4):
                lowNibble = self.x[column][element] & 0x0F
                highNibble = self.x[column][element] >> 4
                self.x[column][element] = int(self.sboxes[highNibble * 16 + lowNibble], 16)
        return self.x
    
    def shift_rows(self):
        clone = []
        for i in range(4):
            clone.append(self.x[i].copy())
        for column in range(1, 4):
            for row in range(4):
                self.x[(row + (4 - column)) % 4][column] = clone[row][column]
        return self.x

    def mix_column(self, round):
        if round != 10:
            clone = []
            for i in range(4):
                clone.append(self.x[i].copy())
            for row in range(4):
                for column in range(4):
                    xor = GF256(clone[row][3]) * MixedColumnTable[column][3]
                    for step in range(3):
                        xor ^= GF256(clone[row][step]) * MixedColumnTable[column][step]
                    self.x[row][column] = int(xor)
        return self.x
  
    def key_addition(self, round):
        for column in range(4):
            for element in range(4):
                self.x[column][element] ^= self.roundkeys[1][column * 4 + element]
        return self.x
    
    def run_round(self, round):
        print("=================")
        print(f"Round {round+1}")
        print("=================")
        print("Byte-Substitution")
        self.byte_substitution()
        print(self.out(self.x))

        print("\nShift-Rows")
        self.shift_rows()
        print(self.out(self.x))

        # MixColumns nur in den ersten 9 Runden anwenden
        if round < 9:  
            print("\nMix Column")
            self.mix_column(round)
            print(self.out(self.x))

        print("\nKey-Addition")
        self.key_addition(round)
        print(self.out(self.x))


    def run(self):
        print("Key-Whitening")
        self.key_whitening()
        print(self.out(self.x))

        for round in range(10):
            self.run_round(round)

            
k = [[0xcd, 0x7d, 0x37, 0x36],
       [0x9a, 0x1d, 0x25, 0x70],
       [0x27, 0xbd, 0x5b, 0x23],
       [0xc8, 0xe5, 0xa1, 0xae]]
x = [[0x5e, 0x8c, 0x1f, 0x48],
     [0x3d, 0x98, 0x61, 0xb3],
     [0xcd, 0xef, 0xf5, 0xca],
     [0x5e, 0xc7, 0xf7, 0xdd]]

# Verwendung
aes = AES(k, x)
aes.run()
