# Gal Ben Arush 208723791 Yoav Berger 313268393

import base64
import hashlib
import math

import cryptography
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import load_pem_public_key


# creating two classes one for the tree and one for the leaves
# the leave holds it's hash value and if the index of it even or odd
# the tree holds the number of leaves he has and two arrays -
# one of the original leaves and the other is copy for messing with functions

''' Even boolean field to sign duality of the index '''
class Merkle_Leaf:
    def __init__(self, data, numOfLeave):
        self.hash = myHash(data)
        if numOfLeave % 2 == 0:
            self.even = True
        else:
            self.even = False

'''
Original array for the leaves of the tree
Chagning array for storing the leaves during the iteration
'''
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

    # input 1
    def insert_leaf(self, leaf):
        self.originalArray.append(leaf)
        self.numOfLeaves += 1

    def createNextLevel(self):
        '''calculating the next level of the tree from the current level.
        in case we have odd amount of leaves, the last one auto moves up to next level'''
        # in case we at the first round
        if len(self.changingArray) == 0:
            self.changingArray = self.originalArray.copy()
        # in case odd leaves move him to next level
        oddleave = None
        if len(self.changingArray) % 2 == 1:
            oddleave = self.changingArray.pop()
        # iterate the list and hash every two leaves
        temp = []
        j = 0
        for i, k in zip(self.changingArray[0::2], self.changingArray[1::2]):
            tmpLeave = Merkle_Leaf(i.hash + k.hash, j)
            temp.append(tmpLeave)
            j += 1
        # in case there was odd num of leaves insert the one we kept to the next level
        # change the even according to new index it will get
        # logic - if len.arr = even => then it's last index is odd
        if oddleave != None:
            if len(temp) % 2 == 0:
                oddleave.even = True
            else:
                oddleave.even = False
            temp.append(oddleave)
        self.changingArray = temp

    # input 2
    def get_root_val(self):
        """recursive function to find the root using createNextLevel function"""
        if len(self.originalArray) == 0:
            return ""
        if len(self.changingArray) == 1:
            return self.changingArray[0].hash
        else:
            self.createNextLevel()
            return self.get_root_val()

    # input 3
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
            leaveNum = math.floor(leaveNum / 2)

        proof = self.get_root_val() + proof
        return proof

    # input 4
    def checkProof(self, leafData, proof):
        '''checking proof of given element. Hashing the given leaf and contionue hashing it with the proof until
        we got to the root'''
        tempHash = myHash(leafData)

        proofArr = proof.split(" ")
        root = proofArr.pop(0)
        for h in proofArr:
            tempStr = h[1:]
            if tempStr != "":
                if h[0] == "0":
                    tempHash = myHash(tempStr + tempHash)
                elif h[0] == "1":
                    tempHash = myHash(tempHash + tempStr)
        if root == tempHash:
            return True
        else:
            return False

    # input 5
    def generateKeys(self):
        '''generate public and private key and convert them to pem format'''
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        pem1 = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                         format=serialization.PrivateFormat.TraditionalOpenSSL,
                                         encryption_algorithm=serialization.NoEncryption()).decode()

        public_key = private_key.public_key()
        pem2 = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                       format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()

        keys = [pem1, pem2]
        return keys

    # input 6
    def signRoot(self, signKey):
        '''check the root and then sign the root with the key'''
        root = self.get_root_val()
        tempKey = load_pem_private_key(signKey.encode(), password=None, backend=default_backend())

        signature = tempKey.sign(root.encode(), padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                            salt_length=padding.PSS.MAX_LENGTH),
                                 hashes.SHA256())
        return (base64.b64encode(signature)).decode()

    # input 7
    def verifySignature(self, publicKey, signature, text):
        '''sign text with public key and verify with the given signature'''
        publicKey = load_pem_public_key(publicKey.encode(), backend=default_backend())
        try:
            publicKey.verify(base64.decodebytes(signature.encode()), text.encode(),
                             padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                             hashes.SHA256())
            return True
        except:
            return False


"""leaf contains data and decimal index of the leaf"""
class SparseLeaf:
    def __init__(self, data, enteredHash):
        self.index = data
        self.hash = enteredHash

"""
Original array for the leaves of the tree
Chagning array for storing the leaves during the iteration
defVal - calculating hash for the current level
"""
class SparseMerkleTree:
    def __init__(self):
        self.indexArray = []
        self.changingArray = []
        self.defValue = "0"

    def printOriginalTree(self):
        for le in self.indexArray:
            print(le.index, le.hash)

    def printCurrentLevel(self):
        for le in self.changingArray:
            print(le.index, le.hash)

    def createNextLevel(self):
        '''calculating the next level of the tree from the current level
        related to the marked leaves'''
        temp = []
        tempHash = ""
        for x in self.changingArray:
            flag = False
            # even leaf case - checking if the brother is marked and calculating the hash accordingly
            # otherwise - calculate the hash with the default value
            if x.index % 2 == 0:
                for y in self.changingArray:
                    if y.index == x.index + 1:
                        tempHash = myHash(x.hash + y.hash)
                        self.changingArray.remove(y)
                        flag = True
                if not flag:
                    tempHash = myHash(x.hash + self.defValue)
            # odd leaf case - checking if the brother is marked and calculating the hash accordingly
            # otherwise - calculate the hash with the default value
            elif x.index % 2 == 1:
                for y in self.changingArray:
                    if y.index == x.index - 1:
                        tempHash = myHash(y.hash + x.hash)
                        self.changingArray.remove(y)
                        flag = True
                if not flag:
                    tempHash = myHash(self.defValue + x.hash)
            leafIndex = math.floor(x.index / 2)
            temp.append(SparseLeaf(leafIndex, tempHash))
        self.changingArray = temp.copy()
        self.defValue = myHash(self.defValue + self.defValue)

    # input 8
    def markLeaf(self, digest):
        index = int(digest, 16)
        isExist = False
        for x in self.indexArray:
            if x.index == index:
                isExist = True
        # for avoiding duplicates
        if not isExist:
            leaf = SparseLeaf(index, "1")
            self.indexArray.append(leaf)

    # input 9
    def getRootVal(self):
        """go over the tree to find the root using createNextLevel function"""
        if len(self.indexArray) == 0:
            tempHash = "0"
            for i in range(256):
                tempHash = myHash(tempHash + tempHash)
            return tempHash
        else:
            self.changingArray = self.indexArray.copy()
            self.defValue = "0"
            for i in range(256):
                self.createNextLevel()
            return self.changingArray[0].hash

    # input 10
    def createProof(self, digest):
        '''creating proof for given digest. checking if the brother leaf or itself are marked and adding the hash
        to the proof. If they are not existed - skip until they are existed'''
        self.changingArray = self.indexArray.copy()
        self.defValue = "0"
        proof = ""
        # special case - check if sparse tree is empty
        if len(self.indexArray) == 0:
            proof = self.getRootVal() + " " + self.getRootVal()
            return proof
        tempIndex = int(digest, 16)
        # create proof 255 times without the root
        for i in range(256):
            broExist = False
            iExist = False
            if tempIndex % 2 == 0:
                for y in self.changingArray:
                    if y.index == tempIndex + 1:
                        proof = proof + " " + y.hash
                        broExist = True
                    elif y.index == tempIndex:
                        iExist = True
                if (not broExist) and iExist:
                    proof = proof + " " + self.defValue
            elif tempIndex % 2 == 1:
                for y in self.changingArray:
                    if y.index == tempIndex - 1:
                        proof = proof + " " + y.hash
                        broExist = True
                    elif y.index == tempIndex:
                        iExist = True
                if (not broExist) and iExist:
                    proof = proof + " " + self.defValue
            # in case of last iteration - do not create the next level
            if i != 255:
                self.createNextLevel()
                tempIndex = math.floor(tempIndex / 2)
        # special case - if we found that half of the tree is empty - create the proof accordingly
        if proof == "":
            if tempIndex % 2 == 0:
                proof = self.defValue + " " + self.changingArray[0].hash
            else:
                proof = self.changingArray[0].hash + " " + self.defValue
        proof = self.getRootVal() + " " + proof
        return proof

    # input 11
    def checkProof(self, digest, num, proof):
        """create proof by given digest and check if we need to mark the leaf. Then we check if the proof
        is match to the given proof"""
        # spliting input to array, poping the empty last element, and creating a tree for the proof validation
        parseInput = proof.split(" ")
        parseInput.pop()
        proofLength = len(parseInput)
        tmp = SparseMerkleTree()

        # in case sign is 1 mark the give leaf
        if num == "1":
            tmp.markLeaf(digest)
        tmp.changingArray = tmp.indexArray.copy()

        # if sign was 0, then creating hash value of zeroes, in case was 1, creating hashes of the given digest
        zero = "0"
        for i in range(256 - (proofLength - 2)):
            if num == "1":
                tmp.createNextLevel()
            elif num == "0":
                zero = myHash(zero + zero)

        # in case sign is zero, check if given first node in proof is equal to the calculated zeroes hash
        # in case sign is one check if given second node in proof is equal to the calculated digest hash
        if num == "0":
            if (zero != parseInput[1]):
                return False
        if num == "1":
            if tmp.changingArray[0].hash != parseInput[2]:
                return False

        # Poping out the root, the given first node which is the zeroes hash and calculating the index of
        # the digest after the hashes
        root = parseInput.pop(0)
        tmpHash = parseInput.pop(0)
        tempIndex = int(digest, 16)
        for p in range(257 - (proofLength - 2)):
            tempIndex = math.floor(tempIndex / 2)

        # according to given diget hash index concating the hashes and compute them
        for x in parseInput:
            if tempIndex % 2 == 1:
                tmpHash = myHash(x + tmpHash)
            else:
                tmpHash = myHash(tmpHash + x)

        # after hashing all of the proof, check if we got the root
        if tmpHash != root:
            return False

        return True


# hash sha256 function
def myHash(value):
    hasher = hashlib.sha256()
    hasher.update(value.encode())
    return hasher.hexdigest()


"""getting user input and executing the appropriate method"""
if __name__ == '__main__':
    merkle = MerkleTree()
    sparse = SparseMerkleTree()
    flag = 0
    while flag == 0:
        # parsing
        userschoice = input()
        parseInput = userschoice.split(" ")

        # choices
        if parseInput[0] == "1":
            leaf = Merkle_Leaf(parseInput[1], merkle.numOfLeaves)
            merkle.insert_leaf(leaf)

        elif parseInput[0] == "2":
            merkle.changingArray = []
            print(merkle.get_root_val())

        elif parseInput[0] == "3":
            merkle.changingArray = []
            print(merkle.createProof(int(parseInput[1])))
        elif parseInput[0] == "4":
            concat = ""
            for i in range(len(parseInput)):
                if i < 2:
                    continue
                else:
                    concat += (parseInput[i] + " ")
            print(merkle.checkProof(parseInput[1], concat))
        elif parseInput[0] == "5":
            keys = merkle.generateKeys()
            print(keys[0])
            print(keys[1])
        elif parseInput[0] == "6":
            allInput = ""
            while userschoice != "":
                allInput += userschoice + "\n"
                userschoice = input()
            print(merkle.signRoot(allInput[2:]))
        elif parseInput[0] == "7":
            publicKey = ""
            while userschoice != "":
                publicKey += userschoice + "\n"
                userschoice = input()
            newInput = input()
            newInput = newInput.split(" ")
            signature = newInput[0]
            text = newInput[1]
            print(merkle.verifySignature(publicKey[2:], signature, text))
        elif parseInput[0] == "8":
            sparse.markLeaf(parseInput[1])
        elif parseInput[0] == "9":
            print(sparse.getRootVal())
        elif parseInput[0] == "10":
            print(sparse.createProof(parseInput[1]))
        elif parseInput[0] == "11":
            concat = ""
            for i in range(len(parseInput)):
                if i < 3:
                    continue
                else:
                    concat += (parseInput[i] + " ")
            print(sparse.checkProof(parseInput[1], parseInput[2], concat))
        else:
            print(" ")

