# n extractor

import sys
import glob
import re
from Crypto.PublicKey import RSA
from Crypto.Util.asn1 import DerSequence
from binascii import a2b_base64
import pgp5parser

def print_rsa_pubkey_n(pem):
	publicKey = RSA.importKey(pem)
	print(hex(publicKey.n)[2:])

def print_cert_pubkey_n(pem):
	# rfc5280
	lines = pem.replace(' ','').split()
	der = a2b_base64(''.join(lines[1:-1]))
	cert = DerSequence()
	cert.decode(der)
	tbsCertificate = DerSequence()
	tbsCertificate.decode(cert[0])
	subjectPublicKeyInfo = tbsCertificate[6]
	print_rsa_pubkey_n(subjectPublicKeyInfo)

def print_ssh2_pubkey_n(pem):
	# rfc4716
	lines = pem.split('\n')
	pubkey = 'ssh-rsa '

	for line in lines:
		if re.match('^---- .*$', line):
			continue
		elif re.match('^.*: .*$', line):
			continue
		else:
			pubkey = pubkey + line.replace('\n','').replace('\r','')

	print_rsa_pubkey_n(pubkey)

def print_pgp_pubkey_n(pem):
	pgp = pgp5parser.PGP5(pem)
	for packet in pgp.getPackets():
		if packet.isPublicKey():
			if packet.rsa_n != None:
				print(packet.rsa_n.hex())

def main():
	argv = sys.argv
	argc = len(argv)

	if (argc != 2):
		print("Usage: python3 ./extract.py keydir/")
		quit()

	keydir = argv[1]
	files = glob.glob(keydir+'/*')

	for fn in files:
		#print(fn)
		f = open(fn)
		lines = f.readlines()
		f.close()
		jlines = ''.join(lines)

		for line in lines:
			if re.match('^$', line):
				continue
			elif re.match('^#', line):
				continue
			elif re.match('^-----BEGIN PGP PUBLIC KEY BLOCK-----$', line):
				print_pgp_pubkey_n(jlines)
				break
			elif re.match('^-----BEGIN CERTIFICATE-----$', line):
				print_cert_pubkey_n(jlines)
				break
			elif re.match('^-----BEGIN RSA PUBLIC KEY-----$', line):
				print_rsa_pubkey_n(jlines)
				break
			elif re.match('^-----BEGIN PUBLIC KEY-----$', line):
				print_rsa_pubkey_n(jlines)
				break
			elif re.match('^---- BEGIN SSH2 PUBLIC KEY ----$', line):
				print_ssh2_pubkey_n(jlines)
				break
			elif re.match('^ssh-rsa .*$', line):
				print_rsa_pubkey_n(line)
				continue
			else:
				#print(line, end="")
				continue

if __name__ == "__main__":
	main()
