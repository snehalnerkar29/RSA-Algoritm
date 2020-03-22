from Crypto.Util.number import *
from Crypto import Random
import Crypto
import gmpy2
import sys

#no of bits for random number 
bits=60
msg="Codemonks"

# Generate the random no with 60 bits

p = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
q = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)

n = p*q
PHI=(p-1)*(q-1)
print("PHI: ",PHI)

#65537 is  possible prime no 
e=65537

# Find modular inverse of e under PHI
d=(gmpy2.invert(e, PHI))

m=  bytes_to_long(msg.encode('utf-8'))

c=pow(m,e, n)
res=pow(c,d ,n)
print("Result: ",res)
print ("Message=%s\np=%s\nq=%s\nN=%s\ncipher=%s\ndecipher=%s" % (msg,p,q,n,c,(long_to_bytes(res))))
OUTPUT:
PHI:  1016464492559216856987135851545817020
Result:  1243958504895116372851
Message=Codemonks
p=962048495784006167
q=1056562633810746971
N=1016464492559216859005746981140570157
cipher=184864765686326963164249014403801494
decipher=b'Codemonks'
B. Factorization Attack
def gcd(a,b): 
    if b==0:
        return a 
    else:
        return gcd(b,a%b)

def encryptRSA(no, e, n):
    encrypted = pow(no, e) % n
    print('Cipher Text = '+ str(encrypted))
    return encrypted

# multipled by  e which will give remainder as 1 when modulo phi 
def decryptRSA(cipherdata, d, n):
    decrypted = pow(cipherdata, d) % n
    print('Decrypted Text = '+ str(decrypted))
    return decrypted

# sample input 
# Enter the value of p = 53
# Enter the value of q = 59
# Enter the value of text = 89

#Message M should always be in between 1 to N-1 to follow the Totient Theorem of Number theory

p = int(input('Enter the value of p = ')) 
q = int(input('Enter the value of q = ')) 
no = int(input('Enter the value of text = ')) 
n = p*q

phi = (p-1)*(q-1)

print('n = ' + str(n))
print('phi = ' + str(phi))

#find e
e = 0
for ee in range(2,phi): 
    if gcd(ee,phi)== 1:
        print('Value of e (public key):' + str(ee))
        e = ee
        break
        
# find d     
for i in range(1,phi): 
    x = 1 + i*phi 
    if x % e == 0: 
        d = int(x/e)
        print("Value of x: ",x)
        print("Value of i: ",i)
        print('Value of d (private key):' + str(d))
        break
		
		
		
encrypted = encryptRSA(no, e, n)
decrypted = decryptRSA(encrypted, d, n)

def isPrime(n): 
    # Corner case 
    if n <= 1 : 
        return False
    # check from 2 to n-1 
    for i in range(2, n): 
        if n % i == 0: 
            return False
  
    return True

def getPrimes(n):
    lst = []
    for i in range(2, n + 1): 
        if isPrime(i): 
            lst.append(i)
    return lst

#Now in factorisation attack we get p and q which are prime and give product as n

def factorisationAttack(n, e, cipherdata):
    primes = getPrimes(n)
    p1 = 0
    q1 = 0
    d1 = 0
    for i in primes:
        for j in primes:
            if i!=j :
                temp = i*j
                if(temp == n):
                    p1 = i
                    q1 = j
                    break;
                
    if(p1 == 0 and q1 == 0):
        print('No p and q found')
        return
    else:
        print('Found p and q')
        print('p: '+ str(p1) +' q:' + str(q1))
        phi = (p1-1)*(q1-1)
        for i in range(1,phi): 
            x = 1 + i*phi 
            if x % e == 0: 
                d1 = int(x/e) 
                break
        decryptRSA(cipherdata, d1, n) 
        print('RSA broken successfully')

# sample input
# Enter the value of cipherdata = 1394
# Enter the value of n = 3127
# Enter the value of e = 3

cipherdata = int(input('Enter the value of cipherdata = ')) 
n = int(input('Enter the value of n = ')) 
e = int(input('Enter the value of e = ')) 

factorisationAttack(n, e, cipherdata)
OUTPUT:
Enter the value of p = 17
Enter the value of q = 7
Enter the value of text = 103
n = 119
phi = 96
Value of e (public key):5
Value of x:  385
Value of i:  4
Value of d (private key):77
Cipher Text = 52
Decrypted Text = 103
Enter the value of cipherdata = 52
Enter the value of n = 119
Enter the value of e = 5
Found p and q
p: 17 q:7
Decrypted Text = 103
RSA broken successfully
