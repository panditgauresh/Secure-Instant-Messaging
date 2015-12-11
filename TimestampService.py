


import time

class TimestampService(object):

    def __init__(self):
        pass

    @staticmethod
    def is_valid(ts):
        st = time.time()
        return abs(st - ts) < 75

    @staticmethod
    def new_timestamp(self):
        return time.time()