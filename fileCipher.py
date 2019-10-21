#!/usr/bin/python
import base64
import argparse
import os
from Crypto.Hash import SHA, HMAC
from Crypto.Cipher import DES3
from Crypto import Random
from Crypto.Util import Counter

mac_length = 20

def file_decrypt(mykey,mytext,outputfile):
   print "###################File Decryption###########################\n" 

   output = base64.decodestring(mytext)
   data = output[:len(output)-mac_length]
   mac  = output[len(output)-mac_length:]
   nonce = data[:DES3.block_size/2]
   iv = data[len(data)-DES3.block_size:]
   encypted = data[DES3.block_size/2:len(data)-DES3.block_size]
     
   ctr = Counter.new(DES3.block_size*8/2, prefix=nonce)
   cipher_decrypt = DES3.new(mykey, DES3.MODE_CTR, iv,counter=ctr)
   decrypted_data = cipher_decrypt.decrypt(encypted)
   new_mac = HMAC.new(mykey, data, SHA)
   verified_mac = new_mac.digest() 
   if mac != verified_mac :
     print '\nThe key %r used is wrong !!' % mykey
     return 0
   
   f = open(outputfile,'w')
   f.write(decrypted_data)
   f.close()
   print '\nThe decryption complete successfully!'
   return 1

def file_encrypt(mykey,payload,outputfile):
   print "###################File Encryption###########################\n" 
   iv = Random.new().read(DES3.block_size) #DES3.block_size==8
   nonce = Random.new().read(DES3.block_size/2) # size of 4
   ctr = Counter.new(DES3.block_size*8/2, prefix=nonce)
   cipher_encrypt = DES3.new(mykey, DES3.MODE_CTR, iv,counter=ctr)
   output=nonce+cipher_encrypt.encrypt(payload)+iv
   mac = HMAC.new(mykey, output, SHA).digest()
   output+=mac
   final = base64.b64encode(output)
   print '\nThe enryption complete successfully!'
   f = open(outputfile,'w')
   f.write(final)
   f.close()

parser = argparse.ArgumentParser(description='File encryption, decryption ')
parser.add_argument('-a','--action', help='Define the action to do (encrypt or decrypt)', default='decrypt')
parser.add_argument('-k','--key', help='The key to use, key size (must be either 16 or 24 bytes long)', type=str, required=True)
parser.add_argument('-f','--file', help='Path to the file to encrypt/decrypt ', type=str, required=True)
parser.add_argument('-o','--output', help='Filename of the decryption output ', type=str, required=True)
args = vars(parser.parse_args())

# Verify that the path file exist
if os.path.isfile(args['file']):
   data = open(args['file'], "rb").read()
else:
   print "The path : %r dosen't exist !!" % args['file']
   quit()

# verify key length :
if len(args['key']) != 16 and  len(args['key']) != 24:
   print "Invalid key size (must be either 16 or 24 bytes long)"
   quit()

if args['action'] == 'decrypt':
## decrypt a file 
  file_decrypt(args['key'],data,args['output'])

## encrypt a file
if args['action'] == 'encrypt':
  data = open(args['file'],'rb').read()
  file_encrypt(args['key'],data,args['output'])
