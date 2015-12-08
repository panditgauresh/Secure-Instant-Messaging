


import time

class TimestampService(object):

    def __init__(self):
        pass

    @staticmethod
    def is_valid(self, ts):
        st = time.time()
        return st - ts < 500

    @staticmethod
    def new_timestamp(self):
        return time.time()