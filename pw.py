#!/usr/bin/env  python3
import hashlib
import pickle
from time import sleep 
from Crypto.Cipher import AES
from os.path import exists
import pprint
import threading
import string
import os
import pyperclip
pwChars=string.printable
def getRandomPassword(nChars):
    pw=""
    rs=os.urandom(1000)# random source
    k=0
    for i in range(nChars):
        while True:
            k=k+1
            b=rs[k]
            if b<100:
                tmp=pwChars[b]
                pw=pw+tmp
                break
    return pw
def changePassword():# also used to define first password
    pwd = input("password=")
    encpwd=pwd.encode('utf-8')
    pwdHash=(hashlib.sha512(encpwd) ).hexdigest()# to be saved to harddisk
    with open("hash.txt", "w") as f:
        f.write(pwdHash)
if not exists("hash.txt"):# User forced to define password
    changePassword()
# key from sha256 hash, first 16 bytes.  Password hash from sha512
def getPassword():
    with open ("hash.txt", "r") as f:
        pwdHashTest=f.read()
    while True:
        pwd = input("password=")
        encpwd=pwd.encode('utf-8')
        pwdHash=(hashlib.sha512(encpwd) ).hexdigest() 
        if  pwdHash == pwdHashTest:
            break
    print("Correct password")
    return pwd
def getKey():
    pwd=getPassword()
    encpwd=pwd.encode('utf-8')
    hashed=hashlib.sha256(encpwd)
    hexkey=hashed.hexdigest()[:32]
    key=hashed.digest()[:16]
    return key,hexkey
key,hexkey=getKey()
def encrypt(data,cipher):
    encryptedData, tag = cipher.encrypt_and_digest(data)
    return encryptedData, tag
def decrypt(data,cipher,tag):
    decryptedData = cipher.decrypt_and_verify(data, tag)
    return decryptedData

def encryptToDisk(pwdData):
    cipher1 = AES.new(key, AES.MODE_EAX)
    nonce=cipher1.nonce
    pwdDump=pickle.dumps(pwdData)
    pwdata,tag=encrypt(pwdDump,cipher1)
    with open("pwdData.bin","wb") as f:
        f.write(nonce)
        f.write(tag)
        f.write(pwdata)
def decryptFromDisk():
    with open("pwdData.bin","rb") as f:
        nonce=f.read(16)
        tag=f.read(16)
        pwdata=f.read()
    cipher2 = AES.new(key, AES.MODE_EAX, nonce)
    tmp=decrypt(pwdata,cipher2,tag)
    pwdData=pickle.loads(tmp)
    return pwdData
tmp=input("""which operation?
1:read, edit and write back
2:initialize table and encrypt to disk 
3:change password
""")
iop=eval(tmp)
if iop == 3:
    changePassword()
elif iop == 2:
    data={} # empty table
    encryptToDisk(data)
elif iop == 1:
    global window
    data=decryptFromDisk()
    pprint.pprint (data)
    # edit dictionary
    while True:
        lser=100
        while (lser > 10):
            service=input("service(at most 10 chars)=")
            lser=len(service) 
        if service == "#":
            break
        tmp=input("""which operation?
        1:edit password
        2:create random password 
        3:copy password to clipboard
        """)
        jop=eval(tmp)
        if jop == 1:
            lpas=100
            while (lpas > 18):
                password=input("password(at most 18 chars)=")
                lpas=len(password)
            if password == "":
            # remove from dictionary
                data.pop(service)
            else:
                data[service]=password
        elif jop == 2:
            password=getRandomPassword(18)
            data[service]=password
        elif jop == 3:
            password=data[service]
            pyperclip.copy(password)
        else:   
            break         
        pprint.pprint (data)
    encryptToDisk(data)
