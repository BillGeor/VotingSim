# -*- coding: utf-8 -*-
"""
Created 12 March 2020
@author: Bill, Phil, Fabien, Danielle
"""

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import hashlib, timeit, signal, random, string


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


"""Represents the CLA"""
class CLA:
    def __init__(self):
        self.ID = "CLA"
        self.__privateKey, self.publicKey = createUserKeys() # the voter's keys
        self.ctf = None
        #list of authorized voters as Hash Table
        self.authList = {}

    #* setting CTF reference through CTF
    def setCTF(self, ctf):
        self.ctf = ctf

    """Authorization Number Request
    Creates random authorization number for a voter
    and adds the voter to the list of authorized voters.
    Nothing is encrypted yet"""
    def authNumRequest(self, voter):
        #assigning an auth num to a voter
        randAuthNum = random.randint(1000,2000)
        #! ENCRYPTION MESSAGE EXCHANGE SIMULATION
        encrNum = self.sendMessage(str(randAuthNum), voter)
        decrNum = voter.recieveMessage(encrNum, self)
        #! ENCRYPTION SIMULATION END
        voter.setAuthNum(decrNum)
        
        #noting the authNum/Voter relation in CLA authList
        self.authList[hashlib.md5(str(voter.authNum).encode()).hexdigest()] = hashlib.md5(str(voter.name).encode()).hexdigest()        
        key = hashlib.md5(str(voter.authNum).encode()).hexdigest()
        value = hashlib.md5(str(voter.name).encode()).hexdigest()
        
        #! ENCRYPTION MESSAGE EXCHANGE SIMULATION
        updatePing = [key, value]
        encUpdate = self.sendMessage(str(updatePing), self.ctf)
        self.ctf.updateList(encUpdate)
        #! ENCRYPTION SIMULATION END
        
        

    def canVote(self, authNumber):
        if(authNumber != None):
            #Check if voter is in CLA list and is authorized to vote
            try:
                self.authList[hashlib.md5(authNumber.encode()).hexdigest()]
                return True
            except KeyError as e:
                # print('User has no auth number', str(e))
                return False
            except IndexError as e:
                # print('User has no auth number.', str(e))
                return False
        else:
            print('User has no auth number')
            return False
        
    #* sends a message to a certain receiver
    def sendMessage(self, plaintext, receiver):
        #enrcypt plaintext using the receiver's public key
        x = encrypt(plaintext, receiver.publicKey)

        #create signature using sender's private key
        s = createSign(self.__privateKey, plaintext)

        encrMessage = [x, s]
        return encrMessage

    #* decrypts a message received by a specific sender
    def recieveMessage(self, encrMessage, sender):
        message = decrypt(
            encrMessage[0], #encrypted message x
            encrMessage[1], #sender's signature s
            self.__privateKey,
            sender.publicKey
        )
        return message


"""Represents CTF"""
class CTF:
    def __init__(self, cla):
        self.ID = "CTF"
        self.__privateKey, self.publicKey = createUserKeys() # the voter's keys
        #list of authorized voters who have not voted yet
        self.notVotedList = {}
        self.options = []
        self.cla = cla
        cla.setCTF(self)

    """Count Vote Stub
    Checks to see if the user is in the list of authorized
    users who haven't yet voted, then either rejects user or
    allows user to vote
    voter - a voter object
    randomVote - if a random vote needs to be calculated or the user will enter a vote"""
    def countVoteRequest(self, voter, randomVote):
        #Check if voter is in CLA list and is authorized to vote
        #! ENCRYPTION MESSAGE EXCHANGE SIMULATION
        encrAuthNum = voter.sendMessage(str(voter.authNum), self)
        decrAuthNum = self.recieveMessage(encrAuthNum, voter)
        #! ENCRYPTION SIMULATION END
        if self.cla.canVote(decrAuthNum):
            #check if voter is in CTF list and has voted
            if (self.voterExists(decrAuthNum) == True):
                #calculate random vote
                if(randomVote):
                    #random vote
                    self.randomVote(voter)
                    #remove voter from list of people who haven't voted
                    del self.notVotedList[hashlib.md5(decrAuthNum.encode()).hexdigest() ]
                else:
                    #allow user to enter a vote manually
                    voter.setVote(input("Please enter your vote: "))
                    #remove voter from list of people who haven't voted
                    del self.notVotedList[hashlib.md5(decrAuthNum.encode()).hexdigest() ]

                #get the vote
                #! ENCRYPTION MESSAGE EXCHANGE SIMULATION
                encrVote = voter.sendMessage(str(voter.vote), self)
                theVote = decrVote = self.recieveMessage(encrVote, voter)
                #! ENCRYPTION SIMULATION END

                #first candidate in list
                if len(self.options) == 0:
                    #create new candidate
                    newCandidate = Candidate()
                    #add to their vote count
                    newCandidate.setNumber(theVote)
                    #add to candidates list
                    self.options.append(newCandidate)

                #if vote has been counted yet
                counted = False
                #count the vote
                for j in range(len(self.options)):
                    #if candidate that is being voted for is in candidates list
                    if self.options[j].candidateNum == theVote:
                        #increase vote count
                        self.options[j].addVote()
                        counted = True
                    #if candidate is not in votes list and vote has not been counted
                    elif j == len(self.options)-1 and counted == False:
                        #make new candidate
                        newCandidate = Candidate()
                        #give candidate a number
                        newCandidate.setNumber(theVote)
                        #add to candidates lsit
                        self.options.append(newCandidate)
                        #add vote
                        self.options[j].addVote()
                        counted = True
                # print("Your vote has been counted!\n")

    #* update an entry from CLA when a user requests and is given an auth number
    def updateList(self, encUpdate):
        decrUpdate = self.recieveMessage(encUpdate, self.cla)
        decrUpdate = decrUpdate[2:len(decrUpdate)-2]
        decrUpdateArr = decrUpdate.split("', '")
        self.notVotedList[decrUpdateArr[0]] = decrUpdateArr[1]
        
    
    def voterExists(self, authNumber):
        #Check if voter is in CLA list and is authorized to vote
        try:
            self.notVotedList[hashlib.md5(authNumber.encode()).hexdigest()]
            return True
        except KeyError as e:
            # print('Voter has Voted',e))
            return False
        except IndexError as e:
            # print('Voter has Voted', str(e))
            return False
    
    """Simulates random vote"""
    def randomVote(self, voter):
        aVote = string.ascii_uppercase[random.randint(0, 3)]
        voter.setVote(aVote)
    
    #* sends a message to a certain receiver
    def sendMessage(self, plaintext, receiver):
        #enrcypt plaintext using the receiver's public key
        x = encrypt(plaintext, receiver.publicKey)

        #create signature using sender's private key
        s = createSign(self.__privateKey, plaintext)

        encrMessage = [x, s]
        return encrMessage

    #* decrypts a message received by a specific sender
    def recieveMessage(self, encrMessage, sender):
        message = decrypt(
            encrMessage[0], #encrypted message x
            encrMessage[1], #sender's signature s
            self.__privateKey,
            sender.publicKey
        )
        return message


"""Represents a candidate"""
class Candidate:
    candidateNum = None
    numVotes = 0
    def addVote(self):
        self.numVotes+=1
    def setNumber(self, num):
        self.candidateNum = num

#* Voter Object
class Voter:
    #* Initializer / Instance Attributes
    def __init__(self):
        self.name = id(self); # the voter's "name"
        # note that the "__" clause in front of private key protects
        #   its access from anyone but the instance of the object itself.
        self.__privateKey, self.publicKey = createUserKeys() # the voter's keys
        self.authNum = None # the voter's authNum (if any)
        self.voted = False # variable of whether voter has voted
        self.vote = None

    #* sets the name of the voter
    def setName(self, newName):
        self.name = newName
    #* sets the vote of the voter
    def setVote(self,voteChoice):
        self.vote = voteChoice
    #* returns the public key of this Voter
    def publicKey(self):
        return self.publicKey
    #* Sets Auth num to received auth num
    def setAuthNum(self, newAuthNum):
        self.authNum = newAuthNum

    #* sends a message to a certain receiver
    def sendMessage(self, plaintext, receiver):
        #enrcypt plaintext using the receiver's public key
        x = encrypt(plaintext, receiver.publicKey)

        #create signature using sender's private key
        s = createSign(self.__privateKey, plaintext)

        encrMessage = [x, s]
        return encrMessage

    #* decrypts a message received by a specific sender
    def recieveMessage(self, encrMessage, sender):
        message = decrypt(
            encrMessage[0], #encrypted message x
            encrMessage[1], #sender's signature s
            self.__privateKey,
            sender.publicKey
        )
        return message


def main():
    voters = []
    start = timeit.default_timer()
    choice = None
    cla = CLA()
    ctf = CTF(cla)
    while ((timeit.default_timer()-start <=60) and choice != '8'):
        print("Voting Simulation")
        print("--------------------")
        print("Number of voters: ", len(voters))
        print("\t1. Make Voters.")
        print("\t2. Simulate Votes.")
        print("\t3. See Results.")
        # print("\t4. Request Voting Authorization.")
        # print("\t5. Cast Vote.")
        # print("\t6. Check Voting Status.")
        # print("\t7. Who Has Voted")
        print("\t4. Quit.\n")
        choice = input(">> ")

        #Make voters
        if choice == '1' and (timeit.default_timer()-start <=60):
            #allow user to re-enter number of voters if the number that
            #requested authorization > number of voters
            okay = False

            #clear list of voters
            voters.clear()

            while (okay != True):
    				#get number of users and how many should request authorization numbers
                numVoters = int(input("How many users would you like (recommended: 50)?\n"))
                requestAuth = int(input("How many voters should request authorization numbers(recommended: 40)?\n"))
    				#make sure it is applicable
                if requestAuth <= numVoters:
    					#this will make the loop stop
                    okay = True
    					#create voters
                    #voter who request an authorization number
                    print("ATTENTION: Do NOT close the terminal! This process takes several seconds due to key generation time!")
                    for i in range (requestAuth):
                        aVoter = Voter()
                        cla.authNumRequest(aVoter)
                        #add voter to list of total voters
                        voters.append(aVoter)
                    #voters who don't want an authorization number
                    for i in range (numVoters-requestAuth):
                        aVoter = Voter()
                        #add voter to list of total voters
                        voters.append(aVoter)
                    print("\nvoters list:")
                    print("name: \tauthNum: ")
                    #print voters and authorization numbers
                    for i in range(len(voters)):
                        print(voters[i].name, "\t", voters[i].authNum)
                else:
                    print("Sorry, there are only {} voters!".format(numVoters))
                print("\n")

        #Simulate random votes
        elif choice == '2'and (timeit.default_timer()-start <=60):
            for j in range(len(ctf.options)):
                ctf.options[j].numVotes = 0
            #while there are people who have not voted
            while len(ctf.notVotedList)!=0:
                #get a random voter
                randomVoter = random.randint(0, len(voters)-1)
                #simulate and count random vote
                ctf.countVoteRequest(voters[randomVoter], True)

            if (len(ctf.notVotedList) == 0):
                print("The list of voters is empty!")
            
            print("Voting process has been completed! Enter '3' to see results.")

        #Voting breakdown
        elif choice == '3' and (timeit.default_timer()-start <=60):

            if len(ctf.options)!=0:
                print ("Here is the voting breakdown:\nCandidate:\tNumber of Votes:")
                for i in range(len(ctf.options)):
                    print(ctf.options[i].candidateNum, "\t\t\t\t", ctf.options[i].numVotes)
            else:
                print("Sorry, the list of candidates is empty!")

        #End simulation
        elif choice == '4' or (timeit.default_timer()-start > 60):
            break
        else:
            print("\n\nUnknown option {}.\n".format(choice))

if __name__ == '__main__':
    main()
