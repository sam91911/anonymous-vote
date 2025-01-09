from Crypto.Hash import SHA256
from Crypto.Random import random, get_random_bytes
from Crypto.Cipher import AES
import json
#define constant parameter for vote system

N = 32
M = 16

#define some function that can be change

def HASH_F(x):
    """
        secure collision resist one-way function
    """
    return SHA256.new(x).digest()
def RANDOM_F():
    """
        secure random function
    """
    return random.getrandbits(N*8)
def SWAP_F(x, k):
    """
        create one to one mapping to 128bit integer
    """
    cipher = AES.new(k, AES.MODE_ECB)
    return int.from_bytes(cipher.encrypt(x.to_bytes(M, "big")))
def INV_SWAP_F(x, k):
    """
        create one to one mapping to 128bit integer
    """
    cipher = AES.new(k, AES.MODE_ECB)
    return int.from_bytes(cipher.decrypt(x.to_bytes(M, "big")))

#define the functions that will be use

class vote_masker:
    def __init__(self):
        self.__vote_mask_0 = {}
        self.__vote_set = set()
        self.__vote_mask_1 = {}
        self.__swap_key = None
        self.__reveal = None
    def set_swap_key(self, k):
        self.__swap_key = k
    def add_voter(self, voters):
        new_voter = voters-self.__vote_set
        new_mask_0 = {voter: RANDOM_F() for voter in new_voter}
        new_mask_1 = {voter: RANDOM_F() for voter in new_voter}
        new_mask_2 = {voter: new_mask_0[voter]^new_mask_1[voter] for voter in new_voter}
        self.__vote_mask_0.update(new_mask_0)
        self.__vote_mask_1.update(new_mask_1)
        self.__vote_set.update(new_voter)
        return new_mask_2, new_mask_1
    def hash_mask(self):
        self.__reveal = {SWAP_F(voter, self.__swap_key): self.__vote_mask_0[voter] for voter in self.__vote_set}
        return HASH_F(json.dumps(self.__reveal).encode())
    def reveal_mask(self):
        return self.__reveal

class vote_announcer:
    def __init__(self):
        self.__vote_mask = {}
        self.__swap_key = None
    def set_swap_key(self, k):
        self.__swap_key = k
    def add_mask(self, new_mask):
        self.__vote_mask.update(new_mask)
    def process_vote(self, votes):
        assert votes.keys() == self.__vote_mask.keys()
        return {SWAP_F(voter, self.__swap_key): self.__vote_mask[voter]^votes[voter] for voter in votes.keys()}

class vote_dispatcher:
    def __init__(self):
        self.__vote_mask = {}
        self.__real_set = set()
        self.__vote_set = set()
        self.__swap_key = None
    def set_swap_key(self, k):
        self.__swap_key = k
    def add_voter(self, voters):
        new_real = voters-self.__real_set
        new_voter = {SWAP_F(voter, self.__swap_key) for voter in new_real}
        assert (new_voter & self.__vote_set) == set()
        self.__real_set.update(new_real)
        self.__vote_set.update(new_voter)
        return new_voter
    def process_mask(self, mask):
        assert set(mask.keys()).issubset(self.__vote_set)
        return {INV_SWAP_F(voter, self.__swap_key): mask[voter] for voter in mask.keys()}

class vote_collector:
    def __init__(self):
        self.__swap_key = None
        self.__vote = {}
    def set_swap_key(self, k):
        self.__swap_key = k
    def collect_vote(self, vote):
        self.__vote.update({SWAP_F(voter, self.__swap_key): vote[voter] for voter in vote.keys()})
    def process_vote(self):
        return self.__vote

class vote_voter:
    def __init__(self):
        pass
    def vote(self, mask, choose):
        return mask^choose
    def sum_vote(self, mask, vote, mask_hash):
        assert mask.keys() == vote.keys()
        hash_r = HASH_F(json.dumps(mask).encode())
        assert hash_r == mask_hash
        votes = [vote[voter]^mask[voter] for voter in mask.keys()]
        result = {}
        for v in votes:
            if v not in result:
                result[v] = 1
            else:
                result[v] += 1
        return result

if __name__ == "__main__":
    n = 1024
    a = vote_masker()
    b = vote_announcer()
    c = vote_dispatcher()
    d = vote_collector()
    v = vote_voter()
    voter_vote = {i: i%7 for i in range(n)}
    print("votes:", voter_vote)
    real_set = set(voter_vote.keys())
    key0 = get_random_bytes(16)
    key1 = get_random_bytes(16)
    a.set_swap_key(key0)
    b.set_swap_key(key0)
    c.set_swap_key(key1)
    d.set_swap_key(key1)
    for s in real_set:
        vote_set = c.add_voter({s})
        mask_2, mask_1 = a.add_voter(vote_set)
        b.add_mask(mask_1)
        real_mask = c.process_mask(mask_2)
        mask_vote = {s: v.vote(real_mask[s], voter_vote[s])}
        d.collect_vote(mask_vote)
    votes = d.process_vote()
    mask_hash = a.hash_mask()
    announce_vote = b.process_vote(votes)
    reveal_mask = a.reveal_mask()
    sum_vote = v.sum_vote(reveal_mask, announce_vote, mask_hash)
    print("vote result:", sum_vote)
