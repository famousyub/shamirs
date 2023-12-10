from binascii import unhexlify
from Crypto.Cipher import AES
from Crypto.Protocol.SecretSharing import Shamir

shares = []
for x in range(2):
    in_str = input("Enter index and share separated by comma: ")
    idx, share = [ strip(s) for s in in_str.split(",") ]
    shares.append((idx, unhexlify(share)))
key = Shamir.combine(shares)

with open("enc.txt", "rb") as fi:
    nonce, tag = [ fi.read(16) for x in range(2) ]
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    try:
        result = cipher.decrypt(fi.read())
        cipher.verify(tag)
        with open("clear2.txt", "wb") as fo:
            fo.write(result)
    except ValueError:
        print ("The shares were incorrect")