import re
from binascii import a2b_base64
from enum import IntEnum

class PGP5:
	# rfc2440
	class Packet:
		class PacketTag(IntEnum):
			PUBLIC_KEY_PACKET = 6
			PUBLIC_SUBKEY_PACKET = 14

		class PublicKeyAlgorithm(IntEnum):
			RSA_ENCRYPT_OR_SIGN = 1
			RSA_ENCRYPT_ONLY = 2
			RSA_SIGN_ONLY = 3

		def __init__(self, ctag, body):
			self.ctag = ctag
			self.rsa_n = None
			self.rsa_e = None

			if self.isPublicKey():
				self.__parse_pubkey(body)

		def isPublicKey(self):
			is_public_key = ( \
				self.ctag == PGP5.Packet.PacketTag.PUBLIC_KEY_PACKET or \
				self.ctag == PGP5.Packet.PacketTag.PUBLIC_SUBKEY_PACKET )
			return is_public_key

		def __parse_pubkey(self, bytes):
			ver = bytes[0]
			if ver != 4:
				raise NotImplementedError('V3 key is not impremented')

			time = bytes[1]<<24 | bytes[2]<<16 | bytes[3]<<8 | bytes[4]
			type = bytes[5]
			if ( \
				type == PGP5.Packet.PublicKeyAlgorithm.RSA_ENCRYPT_OR_SIGN or \
				type == PGP5.Packet.PublicKeyAlgorithm.RSA_ENCRYPT_ONLY or \
				type == PGP5.Packet.PublicKeyAlgorithm.RSA_SIGN_ONLY ):

				next = 6
				n_bit_len = bytes[next]<<8 | bytes[next + 1]
				n_byte_len = int((n_bit_len + 7) / 8)
				start = next + 2
				next = start + n_byte_len
				self.rsa_n = bytes[start:next]

				e_bit_len = bytes[next]<<8 | bytes[next + 1]
				e_byte_len = int((e_bit_len + 7) / 8)
				start = next + 2
				next = start + e_byte_len
				self.rsa_e = bytes[start:next]

	# end of class packet

	def __init__(self, pem):
		lines = pem.split('\n')
		pembody = ''
		self.__packets = []

		for line in lines:
			if re.match('^-----.*$', line):
				continue
			elif re.match('^Version: .*$', line):
				continue
			elif re.match('^=.*$', line):
				continue
			else:
				pembody = pembody + line.replace('\n','').replace('\r','')

		bytes = a2b_base64(pembody)

		i = 0
		while i < len(bytes):
			ctag, body, offset = self.__parse_header(bytes[i:])
			self.__packets.append(PGP5.Packet(ctag, body))
			i = i + offset

	def getPackets(self):
		return self.__packets

	def __parse_new_header(self, bytes):
		ptag = bytes[0]
		ctag = ptag & 0b111111
		hlen = 0
		blen = 0
		blh = bytes[1]

		if blh < 192:
			blen = blh
			hlen = 2
		elif blh <= 223:
			blen = ((blh - 192) << 8) + bytes[2] + 192
			hlen = 3
		elif blh < 255:
			raise NotImplementedError('Partial body length is not impremented')
			blen = 1 << (blh & 0x1f)
			hlen = 2
		else:
			blen = bytes[2]<<24 | bytes[3]<<16 | bytes[4]<<8 | bytes[5]
			hlen = 6

		return ctag, hlen, blen

	def __parse_old_header(self, bytes):
		ptag = bytes[0]
		ctag = (ptag >> 2) & 0b1111
		ltype = ptag & 0b11
		blen = 0

		if ltype == 0:
			blen = bytes[1]
			hlen = 2
		elif ltype == 1:
			blen = bytes[1]<<8 | bytes[2]
			hlen = 3
		elif ltype == 2:
			blen = bytes[1]<<24 | bytes[2]<<16 | bytes[3]<<8 | bytes[4]
			hlen = 5
		else:
			raise ValueError('Invalid length type')

		return ctag, hlen, blen

	def __parse_header(self, bytes):
		ptag = bytes[0]
		ctag = 0
		hlen = 0
		blen = 0

		if ptag & 0b10000000:
			if ptag & 0b01000000:
				ctag, hlen, blen = self.__parse_new_header(bytes)
			else:
				ctag, hlen, blen = self.__parse_old_header(bytes)
		else:
			raise ValueError('PGP format error')

		return ctag, bytes[hlen:hlen+blen], hlen+blen

# end of class PGP5
