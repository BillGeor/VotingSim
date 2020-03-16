
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
import hashlib
import timeit
import signal
import random
import string


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
        #list of authorized voters
        self.authList = []
    
    #* setting CTF reference through CTF
    def setCTF(self, ctf):
        self.ctf = ctf
    
    """Authorization Number Stub
    Creates random authorization number for a voter
    and adds the voter to the list of authorized voters.
    Nothing is encrypted yet"""
    def authNumStub(self, voter):
        randAuthNum = random.randint(1000,2000)
        voter.setAuthNum(randAuthNum)
        self.authList.append(voter)
        self.ctf.notVotedList.append(voter)
        
    def canVote(self, voter):
        #Check if voter is in CLA list and is authorized to vote
        for i in range(len(self.authList)):
            if self.authList[i].authNum == voter.authNum:
                print ("You are authorized to vote!")
                return True
            #Reject user because they are not authorized
            if i == len(self.authList)-1:
                print("You are not authorized to vote!")
                return False
        return False
                
    def hasVoted(self, voter):
        for i in range(len(self.ctf.notVotedList)):
            #check if voter's authNum matches current authNum
            if self.ctf.notVotedList[i].authNum == voter.authNum:
                print("You have not voted yet!")
                return False
            #Reject user because they have already voted
            if i == len(self.ctf.notVotedList)-1:
                print("You have already voted!")
                return True
        return True
    

"""Represents CTF"""
class CTF:
    def __init__(self, cla):
        self.ID = "CTF"
        self.__privateKey, self.publicKey = createUserKeys() # the voter's keys
        #list of authorized voters who have not voted yet
        self.notVotedList = []
        self.votedList = []
        self.options = []
        self.cla = cla
        cla.setCTF(self)
        
    """Count Vote Stub
    Checks to see if the user is in the list of authorized
    users who haven't yet voted, then either rejects user or
    allows user to vote
    voter - a voter object
    randomVote - if a random vote needs to be calculated or the user will enter a vote"""
    def countVoteStub(self, voter):        
        #Check if voter is in CLA list and is authorized to vote
        if self.cla.canVote(voter.authNum):
            #check if voter is in CTF list and has voted
            if (self.cla.hasVoted(voter.authNum) == False):

                #remove voter from list of people who haven't voted and
                #adds that voter to a list of people who have voted
            
                #allow user to enter a vote manually
                voter.setVote(input("Please enter your vote: "))
                #remove voter from list of people who haven't voted
                self.notVotedList.remove(voter.authNum)
                self.votedList.append(voter.authNum)
                    
                #get the vote
                theVote = voter.vote
                
                #if vote has been counted yet
                counted = False
                #count the vote
                for j in range(len(self.options)):
                    #if candidate that is being voted for is in candidates list
                    if self.options[j].candidateNum == theVote:
                        #increase vote count
                        self.options[j].addVote()
                        counted = True
                        print("Your vote has been counted!\n")
            else: 
                print("You have already voted!")
        else: 
            print("You are not eligible to vote!")            
    
    def printVotes(self):
        for i in range(len(self.options)):
            print("The final results are:")
            print(self.options[i].numVotes)
            print("----------------------")
            
    """Simulates random vote"""
    def randomVote(self, voter):
        aVote = string.ascii_uppercase[random.randint(0, 3)]
        voter.setVote(aVote)                 
            
"""Represents a candidate"""
class Candidate:
    candidateNum = None
    numVotes = 0
    def addVote(self):
        self.numVotes+=1
    def setNumber(self, num):
        self.candidateNum = num

#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
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
        print("\t4. Request Voting Authorization.")
        print("\t5. Cast Vote.")
        print("\t6. Check Voting Status.")
        print("\t7. Who Has Voted")
        print("\t8. Quit.\n")
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
                        #give voter an authorization number
                        cla.authNumStub(aVoter)
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
            #while there are people who have not voted
            while len(ctf.notVotedList)!=0:
                #get a random voter
                randomVoter = random.randint(0, len(voters)-1)
                #simulate and count random vote
                ctf.countVoteStub(voters[randomVoter], True)
            
            if (len(ctf.notVotedList) == 0):
                print("The list of voters is empty!")
        
        #Voting breakdown        
        elif choice == '3' and (timeit.default_timer()-start <=60):
            
            if len(ctf.options)!=0:
                print ("Here is the voting breakdown:\nCandidate:\tNumber of Votes:")
                for i in range(len(ctf.options)):
                    print(ctf.options[i].candidateNum, "\t\t\t\t", ctf.options[i].numVotes)
            else:
                print("Sorry, the list of candidates is empty!")
       
        #Give user an authorization number
        elif choice == '4':
            newVoter = Voter()
            theName = input("Please enter your name: ")
            newVoter.setName(theName)
            cla.authNumStub(newVoter)
            voters.append(newVoter)
            print ("Your authorization number is: ", newVoter.authNum)
            
        #Let user vote    
        elif choice == '5':
            theNum = int(input("Please enter your authorization number: "))
            for i in range(len(cla.authList)):
                if cla.authList[i].authNum == theNum:
                    ctf.countVoteStub(cla.authList[i], False)
               
        #Check if user has voted        
        elif choice == '6':
            authNum = int(input("Please enter your authorization number: "))
            for i in range(len(cla.authList)):
                if cla.authList[i].authNum == authNum:
                    if len(ctf.notVotedList) == 0 and cla.canVote(cla.authList[i]):
                        print("You have already voted!")                    
            for i in range(len(ctf.notVotedList)):
                if ctf.notVotedList[i].authNum == authNum:
                    ctf.hasVoted(ctf.notVotedList[i])
        
        #See who has voted and who hasn't
        elif choice == '7':
            print("Voter\tVote Status")
            for i in range(len(voters)):
                if voters[i].vote is None:
                    print(voters[i].name, "\t\t No vote.")
                else:
                    print(voters[i].name, "\t\t Voted.")
                    
        #End simulation
        elif choice == '8' or (timeit.default_timer()-start > 60):
            break 
        else:
            print("\n\nUnknown option {}.\n".format(choice))
       
if __name__ == '__main__':
    main()