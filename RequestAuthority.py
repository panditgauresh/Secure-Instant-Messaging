import ChallengeComm
import Consts as c
import hashlib


class RequestAuthority():
    def __init__(self):
        self.challengeComm = ChallengeComm.ChallengeComm()

    def get_challenge_tupple(self, login_failures):
        """
        :return: The challenge tuple which is the hashed value of the challenge,
        the index of the challenge and the size of the mask.
        """
        chalTup = self.challengeComm.get_next_challenge()
        masksize = self.get_mask_size(login_failures)
        masked = chalTup[0] & ((1<<masksize)-1)
        hash_object = hashlib.sha256(str(masked).encode(c.CHL_ENCODE)).hexdigest()
        return (hash_object, chalTup[1], masksize)

    def get_mask_size(self, login_failures):
        """
        :return: the size of the mask which has to be anded with the challenge
        """
        if login_failures >= 5:
            return 20
        return 17

    def compute_answer(self, chl, k):
        """
        :param chl: Takes in the challenge
        :param k: the index
        :return: computes the value of the challenge based on the challenge hash chl
        """
        return self.challengeComm.compute_challenge(k, chl)