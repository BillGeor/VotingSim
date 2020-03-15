import os, binascii
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

#* creates a public key for a user of the cryptosystem
#*   returns privateKey for the user's private key
#*       and publicKey for user's public key
#!   NOTE: privateKey.public_key() is interchangeable with publicKey
def createUserKeys():
    privateKey = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    publicKey = privateKey.public_key()
    return privateKey, publicKey


#* creates the signature for a message that is to be encrypted
#*   with the sender's private key.
def createSign(privateKey, m):
    m = m.encode()
    signature = privateKey.sign(
        m,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


#* encrypts a given plaintext to a receiver,
#*   using that user's public key
def encrypt(m, publickey):
    m = m.encode() #makes the string m into a bytes object
    ciphertext = publickey.encrypt(
        m,
        padding.OAEP(
            mgf = padding.MGF1(algorithm=hashes.SHA256()),
            algorithm = hashes.SHA256(),
            label = None
        )
    )
    return ciphertext


#* decrypts a given ciphertext using the receiver's
#*   private key and verifies their signature
def decrypt(ciphertext, signature, recipientPrivKey, senderPubKey):
    # ciphertext decryption
    plaintext = recipientPrivKey.decrypt(
        ciphertext,
        padding.OAEP(
            mgf = padding.MGF1(algorithm=hashes.SHA256()),
            algorithm = hashes.SHA256(),
            label = None
        )
    )
    # signature verification
    try:
        senderPubKey.verify(
            signature,
            plaintext,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except:
        print("Signature does not match")
        return None
    plaintext = plaintext.decode()
    return plaintext


#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
class Voter:
    #* Initializer / Instance Attributes
    def __init__(self):
        self.ID = id(self); # the voter's "name"
        self.__privateKey, self.publicKey = createUserKeys() # the voter's keys
        self.authNum = None # the voter's authNum (if any)
        self.voted = False # variable of whether voter has voted
      
    #* returns the public key of this Voter  
    def publicKey(self):
        return self.publicKey
    #* Sets Auth num to received auth num
    def setAuthNum(self, newAuthNum):
        self.authNum = authNum
    
    #* sends a message to a certain receiver
    def sendMessage(self, plaintext, receiverPubKey):
        #enrcypt plaintext using the receiver's public key
        x = encrypt(plaintext, receiverPubKey)
        
        #create signature using sender's private key
        s = createSign(self.__privateKey, plaintext)
        
        encrMessage = [x, s]
        return encrMessage
    
    #* decrypts a message received by a specific sender
    def recieveMessage(self, encrMessage, senderPubKey):
        message = decrypt(
            encrMessage[0],
            encrMessage[1],
            self.__privateKey,
            senderPubKey
        )
        return message
    



#!!! TESTING SEQUENCE !!!#
privateKey, publicKey = createUserKeys()
m = "hello"
s = createSign(privateKey, m)
print(decrypt(encrypt(m, publicKey), s, privateKey, publicKey))
print(m)