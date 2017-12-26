# simple python3 library to allow interaction with remote QRL node using: grpc, xmss, kyber and dilithium, ephemeral

import qrl_pb2, qrl_pb2_grpc
import grpc
from pyqrllib.pyqrllib import bin2hstr, hstr2bin, bin2mnemonic, sha2_256, ucharVector, shake256
from pyqrllib import pyqrllib
from pyqrllib.kyber import Kyber
from pyqrllib.dilithium import Dilithium

from os import urandom


# XMSS via pyqrllib within a class

class Tree():
    def __init__(self, seed=None, height=10):
        if not seed:
            seed = useed()
        if height <3 or height % 2 != 0:            #h=2 or odd -> segfault
            height = 10
        self.seed = seed
        self.hexseed = bin2hstr(self.seed)
        self.mnemonic = bin2mnemonic(self.seed)
        self.xmss = pyqrllib.Xmss(seed=seed, height=height)
        self.PK = self.xmss.getPK()
        self.SK = self.xmss.getSK()
        self.height = self.xmss.getHeight()
        self.signatures = 2**self.height
        self.address = self.xmss.getAddress('Q')

    def set_index(self, index=None):
        if not index or index > 2**self.height:
            return
        self.xmss.setIndex(index)
        return

    def get_index(self):
        return self.xmss.getIndex()

    def remaining(self):
        return self.signatures-self.xmss.getIndex()

    def sign(self, message, index=None):
        if isinstance(message, bytes):                          #if being passed for a tx then it will be bytes already
            return bytes(self.xmss.sign(tuple(message)))
        else:
            return bin2hstr(self.xmss.sign(tuple(message.encode())))

    def verify(self, message, signature, PK):
        return self.xmss.verify(tuple(message.encode()), hstr2bin(signature), PK)


# prf

def prf(seed, m, n, l):             # takes seed, feeds into shake256 and returns PRF sequence of l byte chunks from index m -> n (inclusive, exclusive)

    return prf_output




# grpc functions within a class

class Grpc():
    def __init__(self, node='104.251.219.145:9009'):
        self.grpc_connect(node)

    def grpc_connect(self,node):
        self.channel = grpc.insecure_channel(node)
        self.stub = qrl_pb2_grpc.PublicAPIStub(self.channel)

    def grpc_GetState(self):
        return self.stub.GetStats(qrl_pb2.GetStatsReq())

    def grpc_GetAddressState(self, address):
        addr = self.stub.GetAddressState(qrl_pb2.GetAddressStateReq(address=address.encode())).state
        return addr


    def grpc_GetKnownPeers(self):
        knownpeers = stub.GetKnownPeers(qrl_pb2.GetKnownPeersReq())
        self.peers = []
        for p in knownpeers.known_peers:
            self.peers.append(p.ip)
        return self.peers
                                # NEED TO FIX THE TYPE CHECK FOR TXHASHES and BLOCKHASHES (bytes)
    def grpc_GetObject(self, some_obj):
        obj = stub.GetObject(qrl_pb2.GetObjectReq(query=some_obj))
        if obj.found == True:
           return obj#.address_state                              # obj.address_state.address/nonce/pubhashes/transaction_hashes
        else:
            return False

    def grpc_PushTransaction(self, tx_obj):
        response = self.stub.PushTransaction(qrl_pb2.PushTransactionReq(transaction_signed=tx_obj))
        return response

# open channel

def grpc_connect(node='104.251.219.145:9009'):
    return Grpc(node)

# straight call to a new channel..to be removed after testing..

def grpc_GetAddressState(address, node='104.251.219.145:9009'):
    g = Grpc(node=node)
    return g.grpc_GetAddressState(address)      #returns addr.address, addr.balance, addr.nonce, transaction hashes []

def grpc_PushTransaction(tx_obj, node='104.251.219.145:9009'):               #returns response
    g = Grpc(node=node)
    return grpc_PushTransaction(tx_obj)




# tx/msg functions

"""Minor changes to improve Transaction inheritance planned which will alter both of these functions slightly"""

# transfer
def transfer_tx_object(tree_obj, addr_to, amount=None, fee=None):       #instantiate a Tree() first using seed..
    tx = qrl_pb2.Transaction()
    tx.type = 1
    tx.addr_from = tree_obj.address.encode()
    tx.public_key = bytes(tree_obj.PK)
    tx.ots_key = tree_obj.get_index()
    tx.transfer.addr_to = addr_to.encode()
    tx.transfer.amount = amount
    tx.transfer.fee = fee
    pubhash = bytes(sha256(bytes(tx.public_key) + str(tx.ots_key).encode()))
    tx.transaction_hash = bytes(sha256(bytes(sha256(tx.addr_from+tx.transfer.addr_to+str(tx.transfer.amount).encode()+str(tx.transfer.fee).encode()))+pubhash))
    tx.signature = tree_obj.sign(tx.transaction_hash)
    return tx

# lattice

def lattice_tx_object(tree_obj, kyber_pk, dilithium_pk, fee=None):                                        #instantiate a Tree() first using seed..
    tx = qrl_pb2.Transaction()
    tx.type = 5
    tx.public_key = bytes(tree_obj.PK)
    tx.ots_key = tree_obj.get_index()
    tx.addr_from = tree_obj.address.encode()

    tx.latticePK.kyber = bytes(kyber_pk)
    tx.latticePK.dilithium = bytes(dilithium_pk)

    pubhash = bytes(sha256(bytes(tx.public_key) + str(tx.ots_key).encode()))
    tx.transaction_hash = bytes(sha256(bytes(sha256(tx.latticePK.kyber_pk+tx.latticePK.dilithium_pk))+pubhash)) #this will change..to add addr_from and str(tx.fee).encode
    tx.signature = tree_obj.sign(tx.transaction_hash)
    return tx

# ephemeral

def ephemeral_msg_object(id, ttl, ttr=None, pow_nonce, data):
    eph = qrl_pb2.EphemeralMessage()
    eph.id = id
    eph.ttl = ttl
    eph.ttr = ttr
    eph.pow_nonce = pow_nonce
    eph.data = data
    return eph

# misc functions

def useed(n=48):
    return urandom(n)

def sha256(message: bytes) -> bytes:
    return bytes(sha2_256(message))




# kyber

class Kyb():

    def __init__(self, PK=None, SK=None):
        if not PK or not SK:
            self.k = Kyber()
        else:
            self.k = Kyber(PK, SK)
        self.PK = self.k.getPK()
        self.SK = self.k.getSK()


    def kem_encode(self, kyber_pk):
        self.k.kem_encode(kyber_pk)
        self.ciphertext =  self.k.getCypherText()
        self.shared_secret = self.k.getMyKey()
        return self.ciphertext, self.shared_secret

    def kem_decode(self, ciphertext):
        if self.k.kem_decode(ciphertext) == True:
            self.shared_secret = self.k.getMyKey()
            return self.shared_secret
        else:
            return False


def kyber_newkeys():
    kb = Kyb()
    return kb.SK, kb.PK             #returns kyber SK, kyber SK

def kyber_encode_cipher(PK):
    kb = Kyb()
    return kb.kem_encode(PK)        #returns encrypted cipher and shared secret

def kyber_decode_cipher(ciphertext, SK, PK):          #returns false or shared secret
    kb = Kyb(PK, SK)
    return kb.kem_decode(ciphertext)




# dilithium

class Dil():
    def __init__(self, PK=None, SK=None):
        if not PK or not SK:
            self.d = Dilithium()
        else:
            self.d = Dilithium(PK, SK)
        self.PK = self.d.getPK()
        self.SK = self.d.getSK()

    def sign(self,message):     #message should be bytes
        signature = self.d.sign(message)
        return signature

    def verify(self, message, signature, PK):
        data_out = ucharVector(len(signature))
        self.d.sign_open(data_out, signature, PK)
        message_out = bytes(self.d.extract_message(data_out))
        signature_out = self.d.extract_signature(data_out)
        if message_out != message:
            return False
        if len(signature_out) != 2701:
            return False
        return True


def dilithium_newkeys():
    ds = Dil()
    return ds.SK, ds.PK

def dilithium_sign(SK, PK, message):                    #returns message, signature, PK (Bob)
    if not isinstance(message, bytes):
        message = message.encode()
    ds = Dil(PK, SK)
    signature = ds.sign(message)

    return message, signature, PK

def dilithium_verify(message, signature, PK):           #returns True or False
    ds = Dil()
    return ds.verify(message, signature, PK)




# functions which glom together the above to actually do useful things

"""To send a valid transfer_tx to the network..
1. take seed and generate xmss tree, address, etc
2. query address_state to get last index in chain, confirm sufficient balance, etc
3. create signed transfer_tx_object
4. push tx through grpc
"""

def push_transfer_tx(channel, addr_to, amount= None, fee=None, seed=None, tree_obj=None):
    if tree_obj != None:
        pass
    else:
        tree_obj = Tree(seed=seed, height=10)
    state = channel.grpc_GetAddressState(tree_obj.address)
    index = state.nonce
    tree_obj.set_index(index)                  # set ots_key from chain
    balance = state.balance
    if fee == None:
        fee = 0
    if amount >= balance-fee:           # must be sufficient balance..
        return False
    return channel.grpc_PushTransaction(transfer_tx_object(tree_obj=tree_obj, addr_to=addr_to, amount=amount, fee=fee))


"""To send a valid lattice_tx to the network..
1. take seed and generate xmss tree, address, etc
2. check last used index from the chain
2. create signed lattice_tx_object using supplied keys
3. push tx through grpc
"""

def push_lattice_tx(channel, kyber_pk, dilithium_pk, fee=None, seed=None, tree_obj=None):
    if tree_obj != None:
        pass
    else:
        tree_obj = Tree(seed=seed, height=10)
    state = channel.grpc_GetAddressState(tree_obj.address)
    index = state.nonce
    tree_obj.set_index(index)                  # set ots_key from chain
    return channel.grpc_PushTransaction(lattice_tx_object(tree_obj=tree_obj, kyber_pk=kyber_pk, dilithium_pk=dilithium_pk, fee=fee))


def generate_lattice_keys():                            #from random entropy (update from seed)
    dilithium_sk, dilithium_pk = dilithium_newkeys()
    kyber_sk, kyber_pk = kyber_newkeys()
    return kyber_sk, kyber_pk, dilithium_sk, dilithium_pk


def address_lattice_keys(channel, address):             #return the txhash, lattice keypairs for each channel associated with an address
    state = channel.grpc_GetAddressState(address)
    if not hasattr(state, 'latticePK'):
        return False
    #print(state)
    return state.latticePK


# ephemeral


class Far():
    def __init__(self, address, grpc_channel):
        self.address = address
        self.latticePK = address_lattice_keys(channel=grpc_channel, address=self.address)
        if self.latticePK is not False:
            self.txhash = self.latticePK[0][0]
            self.kyber_pk = self.latticePK[0][1]
            self.dilithium_pk = self.latticePK[0][2]
            self.open = True
        else:
            self.open = False


class Eph():
    def __init__(self, address, grpc_channel, seed=None, tree_obj=None):
        far = Far(address=address, grpc_channel=grpc_channel)
        self.far = far
        if far.open == False:
            print('address:',address, 'closed')
            return
        print('address:', address, 'open')

        # once we have data persistence remove this and call separately only for new..
        self.new_Near(grpc_channel=grpc_channel, far_obj=far, seed=seed, tree_obj=tree_obj)


    def new_Near(self, grpc_channel, far_obj, seed=None, tree_obj=None):
        if tree_obj != None:
            pass
        else:
            tree_obj = Tree(seed=seed, height=10)
        self.address = tree_obj.address
        self.seed = tree_obj.seed
        self.tree_obj = tree_obj
        self.kyber_sk, self.kyber_pk, self.dilithium_sk, self.dilithium_pk = generate_lattice_keys()
        push_lattice_tx(channel=grpc_channel, kyber_pk=self.kyber_pk, dilithium_pk=self.dilithium_pk, tree_obj=self.tree_obj)

        self.prf = useed()
        self.prf_alice = 0
        self.prf_bob = 0
        self.cipher, self.shared_secret = kyber_encode_cipher(self.far.kyber_pk)

    def open_channel(self):
        ttl = 1527897600
        ttr = 1514247867
        pow_nonce = None

        # data blob format: {self.ciphertext, aes_encrypted(self.shared_secret) { prf_seed, qrl_address, dilithium signature, data}

        blob = None

        m, s, pk = dilithium_sign(self.dilithium_sk, self.dilithium_pk, blob)



        self.openmsg = ephemeral_msg_object(id=self.txhash, ttl=ttl, ttr=None, pow_nonce=pow_nonce, data=blob)



        # push to network via grpc call

        return

    def collect_messages(self):
        pass

        # prf sequence, alice odd, Bob even values..

        # spread message request over multiple channels



    def send_message(self):
        pass

        # construct via ephemeral_msg_object()

    





if __name__ == '__main__':

    channel = grpc_connect()

    print(address_lattice_keys(channel, 'Q812f28a47f041be3509f4154a9a9c87b56871576b4a4ba75d5975fc46213d87449bf6dac'))

    seed = useed()
    t = Tree()
    print(seed)
    print(push_transfer_tx(channel, addr_to='Q812f28a47f041be3509f4154a9a9c87b56871576b4a4ba75d5975fc46213d87449bf6dac', amount=10000000, tree_obj=t))


    #stub = grpc_connect('104.251.219.145:9009')

    #print(grpc_GetObject('6cf0a5932b338441f8f7f3ea470e711b4fe48b626135a6af364fa45b302f3c10'))
    #print(grpc_GetObject('e077d5dbb2b4ea367a98320509a63c5242650cf9989cb8a0e23d0724b5c3cff5'))
    #print(grpc_GetObject('Qaa67452ae78f0eea9a4d7bffbec0edd4986592e911a06af999827dca9b4d6e559b61100e'))
    #print(grpc_GetObject('2074bb62a7afdd704462ff7e8f34777729f180c16b38b90c440a2d85a7f6f380'))
    #print(grpc_GetObject('24').block.transactions)
    #print(grpc_GetKnownPeers())
    #print(hstr2bin('2074bb62a7afdd704462ff7e8f34777729f180c16b38b90c440a2d85a7f6f380'))
    #print(grpc_GetObject(hstr2bin('2074bb62a7afdd704462ff7e8f34777729f180c16b38b90c440a2d85a7f6f380')))
