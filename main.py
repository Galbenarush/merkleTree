import base64
import hashlib
import math

import cryptography
from cryptography.hazmat.primitives.asymmetric import rsa, dsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography import x509

# creating two classes one for the tree and one for the leaves
# the leave holds it's hash value and if the index of it even or odd
#the tree holds the number of leaves he has and two arrays - one of the original leaves and the other is copy for meesing with functions
#there is assumption that before every func call changingArray is empty


class Merkle_Leafe:
    def __init__(self , data, numOfLeave):
        self.hash = myHash(data)
        if numOfLeave % 2 == 0:
            self.even = True
        else:
            self.even = False


class MerkleTree:
    def __init__(self):
        self.originalArray = []
        self.changingArray = []
        self.numOfLeaves = 0

    def printOriginalTree(self):
        for le in self.originalArray:
            print(le.hash, le.even)

    def printCurrentLevel(self):
        for le in self.changingArray:
            print(le.hash, le.even)

    def insert_leaf(self, leaf):
        self.originalArray.append(leaf)
        self.numOfLeaves += 1


    def createNextLevel(self):
        '''calculating the next level of the tree from the current level.
        in case we have odd amount of leaves, the last one auto moves up to next level'''
        #in case we at the first round
        if len(self.changingArray) == 0:
            self.changingArray = self.originalArray.copy()
        #in case odd leaves move him to next level
        oddleave = None
        if len(self.changingArray) % 2 == 1:
            oddleave = self.changingArray.pop()
        #iterate the list and hash every two leavs
        temp = []
        j = 0
        for i, k in zip(self.changingArray[0::2], self.changingArray[1::2]):
            tmpLeave = Merkle_Leafe(i.hash+k.hash, j)
            temp.append(tmpLeave)
            j += 1
        #in case there was odd num of leaves insert the one we kept to the next level
        #change the even according to new index it will get
        # logic - if len.arr = even => then it's last index is odd
        if oddleave != None:
            if len(temp) % 2 == 0:
                oddleave.even = True
            else:
                oddleave.even = False
            temp.append(oddleave)
        self.changingArray = temp

    def get_root_val(self):
        if(len(self.originalArray) == 0):
            return ""
        if len(self.changingArray) == 1:
            return self.changingArray[0].hash
        else:
            self.createNextLevel()
            return self.get_root_val()

    def createProof(self, leaveNum):
        '''creating proof for given leaf. initialize the cahnge arr, until geting the root shrink the tree and get
        the right part of the proof. 3 cases: 1. in case asking for the last leaf in odd arr, we dont take any hash for
        the proof. 2. in case leaf index is odd we take the hash to our left, if even so to our right. 3. the index
        alway divided by 2 round down, in the next level'''
        proof = ""
        if len(self.changingArray) == 0:
            self.changingArray = self.originalArray.copy()

        while len(self.changingArray) != 1:
            if len(self.changingArray) - 1 == leaveNum and len(self.changingArray) % 2 == 1:
                pass
            elif self.changingArray[leaveNum].even == False:
                proof = proof + " 0" + self.changingArray[leaveNum - 1].hash
            else:
                proof = proof + " 1" + self.changingArray[leaveNum + 1].hash
            self.createNextLevel()
            leaveNum = math.floor(leaveNum/2)

        proof = self.get_root_val() + proof
        return proof

    def checkProof(self, leafData, proof):
        '''checking proof of given element. Hashing the given leaf and contionue hashing it with the proof until
        we got to the root'''
        tempHash = myHash(leafData)

        proofArr = proof.split(" ")
        root = proofArr.pop(0)
        for h in proofArr:
            tempStr = h[1:]
            tempHash = myHash(tempHash+tempStr)

        if root == tempHash:
            return True
        else:
            return False

    # input 5
    def generateKeys(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        pem1 = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                                        encryption_algorithm=serialization.NoEncryption()).decode()

        public_key = private_key.public_key()
        pem2 = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                      format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()

        keys = [private_key, public_key]
        print("private: ")
        print(pem1)
        print("public: ")
        print(pem2)
        return keys

    # input 6
    def signRoot(self, signKey):
        root = self.get_root_val()
        tempKey = load_pem_private_key(signKey.encode(), password=None, backend=default_backend())
        print("Temp: ", tempKey)

        signature = tempKey.sign(root.encode(), padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                   salt_length=padding.PSS.MAX_LENGTH),
                                 hashes.SHA256())
        print("old signature: ", signature)
        print((base64.b64encode(signature)).decode())
        return (base64.b64encode(signature)).decode()

    # input 7
    def verifySignature(self, verKey, signa, verText):
        newSignature = base64.decodebytes(signa.encode())
        print("new signature:", newSignature)
        newVerkey = load_pem_public_key(verKey.encode(), backend=default_backend())
        try:
            newVerkey.verify(newSignature, verText.encode(), padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                        salt_length=padding.PSS.MAX_LENGTH),
                                    hashes.SHA256())
            print(True)
            return True
        except cryptography.exceptions.InvalidSignature:
            print(False)
            return False




# hash sha256 function
def myHash(value):
    hasher = hashlib.sha256()
    hasher.update(value.encode())
    return hasher.hexdigest()

# tests
if __name__ == '__main__':
    merkle = MerkleTree()
    flag = 0
    while(flag == 0):
        #parsing
        userschoice = input()
        parseInput = userschoice.split(" ")

        #choices
        if(parseInput[0] == "1"):
            leaf = Merkle_Leafe(parseInput[1], merkle.numOfLeaves)
            merkle.insert_leaf(leaf)

        elif (parseInput[0] == "2"):
            print(merkle.get_root_val())

        elif (parseInput[0] == "3"):
            merkle.changingArray = []
            print(merkle.createProof(int(parseInput[1])))
            flag = 1


    #creating tree and inserting leaves
    # merkle = MerkleTree()
    # leaf1 = Merkle_Leafe("a", merkle.numOfLeaves)
    # merkle.insert_leaf(leaf1)
    # print("the original tree:")
    # merkle.printOriginalTree()
    # print("current root")
    # print(merkle.get_root_val())

    # leaf2 = Merkle_Leafe("b", merkle.numOfLeaves)
    # merkle.insert_leaf(leaf2)
    # print("the original tree:")
    # merkle.printOriginalTree()
    # merkle.changingArray = []
    # print("current root")
    # print(merkle.get_root_val())
    #
    # leaf3 = Merkle_Leafe("c", merkle.numOfLeaves)
    # merkle.insert_leaf(leaf3)
    # print("the original tree:")
    # merkle.printOriginalTree()
    # merkle.changingArray = []
    # print("current root")
    # print(merkle.get_root_val())
    #printing
    # print("number of leaves on the tree ", merkle.numOfLeaves)
    # print("the original tree:")
    # merkle.printOriginalTree()
    # # creating next level and print it
    # print("next level:")
    # merkle.createNextLevel()
    # merkle.printCurrentLevel()
    # print("next level:")
    # merkle.createNextLevel()
    # merkle.printCurrentLevel()
    # print("root result:")
    # print(merkle.get_root_val())
    #
    #
    # merkle.changingArray = []
    # print("proof:")
    # print(merkle.createProof(0))
    #
    # print("check proof:")
    # print(merkle.checkProof("a","d71dc32fa2cd95be60b32dbb3e63009fa8064407ee19f457c92a09a5ff841a8a 13e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d 12e7d2c03a9507ae265ecf5b5356885a53393a2029d241394997265a1a25aefc6"))
    # merkle.generateKeys()
    # private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    # pem1 = private_key.private_bytes(encoding=serialization.Encoding.PEM,
    #                                  format=serialization.PrivateFormat.TraditionalOpenSSL,
    #                                  encryption_algorithm=serialization.NoEncryption())
    # public_key = private_key.public_key()
    # pem2 = public_key.public_bytes(encoding=serialization.Encoding.PEM,
    #                                format=serialization.PublicFormat.SubjectPublicKeyInfo)
    #
    # signature = merkle.signRoot(pem1.decode())
    # merkle.verifySignature(pem2.decode(), signature, "Hello World")