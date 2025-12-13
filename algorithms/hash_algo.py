
import hashlib


class HashAlgorithm:


    @staticmethod
    def md5(data):

        return hashlib.md5(data.encode()).hexdigest()

    @staticmethod
    def sha1(data):
        
        return hashlib.sha1(data.encode()).hexdigest()