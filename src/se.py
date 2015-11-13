import os
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

# h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
# h.update(b"message to hash")
# h.finalize()

#>>> backend = default_backend()
#>>> key = os.urandom(32)
#>>> iv = os.urandom(16)
#>>> cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
#>>> encryptor = cipher.encryptor()
#>>> ct = encryptor.update(b"a secret message") + encryptor.finalize()
#>>> decryptor = cipher.decryptor()
#>>> decryptor.update(ct) + decryptor.finalize()

def xor(x, y):
    z = "".join(map(lambda (xx, yy): chr(ord(xx) ^ ord(yy)), zip(x, y)))
    return z.encode("hex")

def randomTLV(offset, size, encrypted):
    t = 0 # param?
    l = size
    v = os.urandom(l)
    return TLV(offset, t, l, v, encrypted)

class TLV(object):
    def __init__(self, offset, t, l, v, encrypted = False):
        self.offset = offset
        self.t = t # 2b
        self.l = l # 2b
        self.v = v # lb
        self.encrypted = encrypted

# Create the random TLV
tlvs = []
for i in range(20):
    if i % 5 == 0:
        tlvs.append(randomTLV(i, 100, True))
    else:
        tlvs.append(randomTLV(i, 100, False))

backend = default_backend()

cts = []
tags = []

# Initial cipher context
key = os.urandom(32)
iv = os.urandom(16)
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
encryptor = cipher.encryptor()

# mcTLS:
# 1. Each context has a read key and a write key (each are four separate keys for each direction...):
# <see paper for how keys are derived...>

ptmacer = hmac.HMAC(key, hashes.SHA256(), backend=backend)

## NOTE: the context KeyIds would be in the start of the message, after the name
## NOTE: KeyIds map to Kreaders or Kwriters
## NOTE: this assumes something about the packet format--we want something like mcTLS,
# where each record has three MACs
## NOTE: this is like combining selective and multi-context encryption together

# TODO: start with single-context first, and then move to multi-context

# Walk over the list of TLVs and encrypt/MAC encrypted or sensitive ones as necessary
string = False
stream = []
for index, tlv in enumerate(tlvs):
    if tlv.encrypted: # if it's encrypted
        if not string: # if it's the start of a new set of adjacent TLVs, create the new cipher context
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
            encryptor = cipher.encryptor()
            string = True
        ct = encryptor.update(tlv.v)
        stream.append(ct)

        cts = cts + [ct]
        # print cts
    else:
        string = False
        ptmacer.update(tlv.v)

        if (len(stream) > 0):
            macer = hmac.HMAC(key, hashes.SHA256(), backend=backend)
            macer.update("".join(stream))
            tags.append((iv, macer.finalize()))
        stream = []
    pass

# Merge the different macs together
MAC_LENGTH = 32 # 256 bits, for SHA256-based HMAC
merged_mac = "0" * MAC_LENGTH
ivs = ""
for index, (iv, tag) in enumerate(tags):
    ivs += str(iv)
    merged_mac = xor(merged_mac, tag)

# MAC the (IV, tag) tuples and dump the output
ptmacer.update(ivs)
ptmacer.update(merged_mac)

pttag = ptmacer.finalize()

print "".join(cts)
print iv, merged_mac, pttag
