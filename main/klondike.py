import base64
from itertools import islice, starmap

def hamming (i1,i2):
    return sum(starmap(lambda x,y: bin(x^y)[2:].count('1'),zip(i1,i2)))

def get_keydistance(klen, t):
    return hamming(islice(t, 0, klen),islice(t, klen, klen*2)) / klen

def get_autocorrelation(klen, t):
    return hamming(islice(t, 0, None),islice(t, klen, None)) / (len(t)-klen)

with open("rabbit.base64", 'rb') as reader:
#with open("6.txt", 'rb') as reader:
    t64 = reader.read()
    t = base64.b64decode(t64)

dist=20
print("\n".join(("%d %f" %(klen, get_keydistance(klen,t))) for klen in range(1,dist)))
print("\n".join(("%d %f" %(klen, get_autocorrelation(klen,t))) for klen in range(1,dist)))
