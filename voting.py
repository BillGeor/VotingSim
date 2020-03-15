
# -*- coding: utf-8 -*-
"""
Created 12 March 2020 

@author: Bill, Phil, Fabien, Danielle
"""

import hashlib
import timeit
import signal
import random
import string

"""Represents the CLA"""
class CLA:
    #list of authorized voters
    authList = []
    
    """Authorization Number Stub
    Creates random authorization number for a voter
    and adds the voter to the list of authorized voters.
    Nothing is encrypted yet"""
    def authNumStub(self, voter):
        randAuthNum = random.randint(1000,2000)
        voter.setAuthNum(randAuthNum)
        self.authList.append(voter)
        CTF.notVotedList.append(voter)
        
def canVote(voter):
    #Check if voter is in CLA list and is authorized to vote
    for i in range(len(CLA.authList)):
        if CLA.authList[i].authNum == voter.authNum:
            print ("You are authorized to vote!")
            return True
        #Reject user because they are not authorized
        if i == len(CLA.authList)-1:
            print("You are not authorized to vote!")
            return False
    return False
            
def hasVoted(voter):
    for i in range(len(CTF.notVotedList)):
        #check if voter's authNum matches current authNum
        if CTF.notVotedList[i].authNum == voter.authNum:
            print("You have not voted yet!")
            return False
        #Reject user because they have already voted
        if i == len(CTF.notVotedList)-1:
            print("You have already voted!")
            return True
    return True
    

"""Represents CTF"""
class CTF:
    #list of authorized voters who have not voted yet
    notVotedList = []
    options = []
    
    """Count Vote Stub
    Checks to see if the user is in the list of authorized
    users who haven't yet voted, then either rejects user or
    allows user to vote
    voter - a voter object
    randomVote - if a random vote needs to be calculated or the user will enter a vote"""
    def countVoteStub(self,voter, randomVote):        
        #Check if voter is in CLA list and is authorized to vote
        if canVote(voter):
            #check if voter is in CTF list and has voted
            if (hasVoted(voter) == False):
                #calculate random vote
                if(randomVote):
                    #random vote
                    self.randomVote(voter)
                    #remove voter from list of people who haven't voted
                    self.notVotedList.remove(voter)
                else:
                    #allow user to enter a vote manually
                    voter.setVote(input("Please enter your vote: "))
                    #remove voter from list of people who haven't voted
                    self.notVotedList.remove(voter)
                    
                #get the vote
                theVote = voter.vote
                
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
                print("Your vote has been counted!\n")
               
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

"""Represents a voter"""
class Voter:
    authNum = None
    name = None
    vote = None
    def setAuthNum(self,number):
        self.authNum = number
    def setName(self,voterName):
        self.name = voterName
    def setVote(self,voteChoice):
        self.vote = voteChoice
    def randomName(self):
        self.name = string.ascii_uppercase[random.randint(0, 25)]+string.ascii_uppercase[random.randint(0, 25)]+string.ascii_uppercase[random.randint(0, 25)]+string.ascii_uppercase[random.randint(0, 25)]


def main():
    public_key_file = None
    private_key_file = None
    public_key = None
    private_key = None
    voters = []
    start = timeit.default_timer()
    choice = None
    cla = CLA()
    ctf = CTF()
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
                numVoters = int(input("How many users would you like?\n"))
                requestAuth = int(input("How many voters should request authorization numbers?\n"))
    				#make sure it is applicable
                if requestAuth <= numVoters:
    					#this will make the loop stop
                    okay = True
    					#create voters
                    #voter who request an authorization number
                    for i in range (requestAuth):
                        aVoter = Voter()
                        aVoter.randomName()
                        #give voter an authorization number
                        cla.authNumStub(aVoter)
                        #add voter to list of total voters
                        voters.append(aVoter)
                    #voters who don't want an authorization number
                    for i in range (numVoters-requestAuth):
                        aVoter = Voter()
                        aVoter.randomName()
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
                    if len(ctf.notVotedList)==0 and canVote(cla.authList[i]):
                        print("You have already voted!")                    
            for i in range(len(ctf.notVotedList)):
                if ctf.notVotedList[i].authNum == authNum:
                    hasVoted(ctf.notVotedList[i])
        
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