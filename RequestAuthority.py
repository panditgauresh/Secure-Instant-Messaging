from multiprocessing.connection import answer_challenge
import ChallengeComm
import datetime
import hashlib


class RequestAuthority():
    def __init__(self):
        self.challengeComm = ChallengeComm.ChallengeComm()

    def get_challenge_tupple(self):
        """
        :return: The challenge tuple which is the hashed value of the challenge,
        the index of the challenge and the size of the mask.
        """
        chalTup = self.challengeComm.getNextChallenge()
        masksize = self.get_mask_size()
        masked = chalTup[0] & ((1<<masksize)-1)
        hash_object = hashlib.sha256(str(masked).encode('utf-8')).hexdigest()
        return (hash_object, chalTup[1], masksize)

    def get_mask_size(self):
        """
        :return: the size of the mask which has to be anded with the challenge
        """
        return 17

    def compute_answer(self, chl, k):
        """
        :param chl: Takes in the challenge
        :param k: the index
        :return: computes the value of the challenge based on the challenge hash chl
        """
        return self.challengeComm.computeChallenge(k, chl)