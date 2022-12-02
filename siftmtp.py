#python3

import socket
from Crypto import Random
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA

class SiFT_MTP_Error(Exception):

	def __init__(self, err_msg):
		self.err_msg = err_msg

class SiFT_MTP:
	def __init__(self, peer_socket):

		self.DEBUG = True
		# --------- CONSTANTS ------------
		self.version_major = 1
		self.version_minor = 0
		self.mac_len = 12
		self.rsa_key_len = 256
		self.msg_hdr_rsv = b'\x00\x00'
		self.msg_hdr_ver = b'\x01\x00'
		self.size_msg_hdr = 16
		self.size_msg_hdr_ver = 2
		self.size_msg_hdr_typ = 2
		self.size_msg_hdr_len = 2
		self.size_msg_hdr_sqn = 2
		self.size_msg_hdr_rnd = 6
		self.size_msg_hdr_rsv = 2
		self.type_login_req =    b'\x00\x00'
		self.type_login_res =    b'\x00\x10'
		self.type_command_req =  b'\x01\x00'
		self.type_command_res =  b'\x01\x10'
		self.type_upload_req_0 = b'\x02\x00'
		self.type_upload_req_1 = b'\x02\x01'
		self.type_upload_res =   b'\x02\x10'
		self.type_dnload_req =   b'\x03\x00'
		self.type_dnload_res_0 = b'\x03\x10'
		self.type_dnload_res_1 = b'\x03\x11'
		self.msg_types = (self.type_login_req, self.type_login_res,
						  self.type_command_req, self.type_command_res,
						  self.type_upload_req_0, self.type_upload_req_1, self.type_upload_res,
						  self.type_dnload_req, self.type_dnload_res_0, self.type_dnload_res_1)
		# --------- STATE ------------
		self.peer_socket = peer_socket
		self.msg_sqn = b'\x00'

		self.aes_key = None


	# parses a message header and returns a dictionary containing the header fields
	def parse_msg_header(self, msg_hdr):

		parsed_msg_hdr, i = {}, 0
		parsed_msg_hdr['ver'], i = msg_hdr[i:i+self.size_msg_hdr_ver], i+self.size_msg_hdr_ver
		parsed_msg_hdr['typ'], i = msg_hdr[i:i+self.size_msg_hdr_typ], i+self.size_msg_hdr_typ
		parsed_msg_hdr['len'], i = msg_hdr[i:i+self.size_msg_hdr_len], i+self.size_msg_hdr_len
		parsed_msg_hdr['sqn'], i = msg_hdr[i:i+self.size_msg_hdr_sqn], i+self.size_msg_hdr_sqn
		parsed_msg_hdr['rnd'], i = msg_hdr[i:i+self.size_msg_hdr_rnd], i+self.size_msg_hdr_rnd
		parsed_msg_hdr['rsv'] = msg_hdr[i:i+self.size_msg_hdr_rsv]
		return parsed_msg_hdr


	# receives n bytes from the peer socket
	def receive_bytes(self, n):

		bytes_received = b''
		bytes_count = 0
		while bytes_count < n:
			try:
				chunk = self.peer_socket.recv(n-bytes_count)
			except:
				raise SiFT_MTP_Error('Unable to receive via peer socket')
			if not chunk:
				raise SiFT_MTP_Error('Connection with peer is broken')
			bytes_received += chunk
			bytes_count += len(chunk)
		return bytes_received


	# sends all bytes provided via the peer socket
	def send_bytes(self, bytes_to_send):
		try:
			self.peer_socket.sendall(bytes_to_send)
		except:
			raise SiFT_MTP_Error('Unable to send via peer socket')


	# -----------------------------------------------------------------------------------------
	# MTP protocol for sending/recieving ordinary messages (NOT login requests/responses)
	# -----------------------------------------------------------------------------------------


	# receives and parses message, returns msg_type and msg_payload
	def receive_msg(self):

		# receive and check the header
		try:
			msg_hdr = self.receive_bytes(self.size_msg_hdr)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message header --> ' + e.err_msg)

		if len(msg_hdr) != self.size_msg_hdr:
			raise SiFT_MTP_Error('Incomplete message header received')

		parsed_msg_hdr = self.parse_msg_header(msg_hdr)

		if parsed_msg_hdr['ver'] != self.msg_hdr_ver:
			raise SiFT_MTP_Error('Unsupported version found in message header')

		if parsed_msg_hdr['typ'] not in self.msg_types:
			raise SiFT_MTP_Error('Unknown message type found in message header')

		thissqn = int.from_bytes(parsed_msg_hdr['sqn'], byteorder='big')
		if thissqn <= self.msg_sqn:
			raise SiFT_MTP_Error("Error: Message sequence number is too old!")

		msg_len = int.from_bytes(parsed_msg_hdr['len'], byteorder='big')

		# receive the bytes of the (encrypted) payload and the mac
		try:
			msg_body = self.receive_bytes(msg_len - self.size_msg_hdr)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message body --> ' + e.err_msg)

		if len(msg_body) != msg_len - self.size_msg_hdr:
			raise SiFT_MTP_Error('Incomplete message body reveived')

		# Check mac value of payload and decrypt
		nonce = self.msg_sqn + self.msg_hdr_rsv
		AE = AES.new(self.aes_key, AES.MODE_GCM, nonce=nonce, mac_len=self.mac_len)
		AE.update(msg_hdr)

		#TODO: Not sure if this sequencing is correct...check with @trinity
		mac_start_index = msg_len - self.size_msg_hdr
		encrypted_msg_payload = msg_body[:mac_start_index]
		mac = msg_body[mac_start_index:]

		try:
			payload = AE.decrypt_and_verify(encrypted_msg_payload, mac)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('MAC verification failed' + e.err_msg)


		# DEBUG
		if self.DEBUG:
			print('MTP message received (' + str(msg_len) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('BDY (' + str(len(msg_body)) + '): ')
			print(msg_body.hex())
			print('------------------------------------------')
		# DEBUG

		return parsed_msg_hdr['typ'], payload


	# builds and sends message of a given type using the provided payload
	def send_msg(self, msg_type, msg_payload):

		# build message
		msg_size = self.size_msg_hdr + len(msg_payload) + self.mac_len
		msg_hdr_len = msg_size.to_bytes(self.size_msg_hdr_len, byteorder='big')
		msg_hdr_rnd = Random.get_random_bytes(self.size_msg_hdr_rnd)
		msg_hdr = self.msg_hdr_ver + msg_type + msg_hdr_len + self.msg_sqn + msg_hdr_rnd + self.msg_hdr_rsv

		# encrypt payload and compute mac
		nonce = self.msg_sqn + msg_hdr_rnd
		AE = AES.new(self.aes_key, AES.MODE_GCM, nonce=nonce, mac_len=self.mac_len)
		AE.update(msg_hdr)
		encrypted_msg_payload, mac = AE.encrypt_and_digest(msg_payload)

		# DEBUG
		if self.DEBUG:
			print('MTP message to send (' + str(msg_size) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('BDY (' + str(len(msg_payload)) + '): ')
			print(msg_payload.hex())
			print('------------------------------------------')
		# DEBUG

		# try to send
		try:
			self.send_bytes(msg_hdr + encrypted_msg_payload + mac)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to send message to peer --> ' + e.err_msg)

		self.msg_sqn += 1

	# -----------------------------------------------------------------------------------------
	# MTP protocol for sending/recieving login requests/responses
	# -----------------------------------------------------------------------------------------


	# receives and parses login request, returns the message payload
	def receive_login_req(self):

		# receive and check the header
		try:
			msg_hdr = self.receive_bytes(self.size_msg_hdr)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message header --> ' + e.err_msg)

		if len(msg_hdr) != self.size_msg_hdr:
			raise SiFT_MTP_Error('Incomplete message header received')

		parsed_msg_hdr = self.parse_msg_header(msg_hdr)

		if parsed_msg_hdr['ver'] != self.msg_hdr_ver:
			raise SiFT_MTP_Error('Unsupported version found in message header')

		if parsed_msg_hdr['typ'] not in self.msg_types:
			raise SiFT_MTP_Error('Unknown message type found in message header')

		thissqn = int.from_bytes(parsed_msg_hdr['sqn'], byteorder='big')
		if thissqn <= self.msg_sqn:
			raise SiFT_MTP_Error("Error: Message sequence number is too old!")

		msg_len = int.from_bytes(parsed_msg_hdr['len'], byteorder='big')

		# receive the bytes of the (encrypted) payload and the mac
		try:
			msg_body_and_mac = self.receive_bytes(msg_len - (self.size_msg_hdr + 256))
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message body --> ' + e.err_msg)

		if len(msg_body_and_mac) != msg_len - (self.size_msg_hdr + 256):
			raise SiFT_MTP_Error('Incomplete message body reveived')

		encrypted_msg_payload = msg_body_and_mac[:-self.mac_len]
		msg_mac = msg_body_and_mac[-self.mac_len:]

		# receive the RSA encrypted key
		try:
			enc_temp_key = self.receive_bytes(256)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive RSA-encrypted key --> ' + e.err_msg)

		if len(enc_temp_key) != 256:
			raise SiFT_MTP_Error('Incomplete RSA-encrypted key reveived')

		# decrypt RSA-encrypted key using server's private key
		aes_key = dec(enc_temp_key)

		# check mac value of payload and decrypt
		nonce = self.msg_sqn + self.msg_hdr_rsv
		AE = AES.new(aes_key, AES.MODE_GCM, nonce=nonce, mac_len=self.mac_len)
		AE.update(msg_hdr)

		try:
			payload = AE.decrypt_and_verify(encrypted_msg_payload, msg_mac)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('MAC verification failed' + e.err_msg)


		# DEBUG
		if self.DEBUG:
			print('MTP message received (' + str(msg_len) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('BDY (' + str(len(msg_body)) + '): ')
			print(msg_body.hex())
			print('------------------------------------------')
		# DEBUG

		return payload

	#######################################do we need to do something with the sqn here?
	# builds and sends login requests
	def send_login_req(self, msg_payload):

		# build message header
		msg_size = self.size_msg_hdr + len(msg_payload) + self.mac_len + self.rsa_key_len
		msg_type = b'\x00\x00'                                                    # the message type for login requests
		msg_hdr_len = msg_size.to_bytes(self.size_msg_hdr_len, byteorder='big')
		msg_hdr_rnd = Random.get_random_bytes(self.size_msg_hdr_rnd)
		msg_hdr = self.msg_hdr_ver + msg_type + msg_hdr_len + self.msg_sqn + msg_hdr_rnd + self.msg_hrd_rsv

		# generate temporary AES key for encryption of login message payload
		temp_login_req_key = Random.get_random_bytes(32)

		# encrypt payload and compute mac
		nonce = self.msg_sqn + self.msg_hdr_rnd
		AE = AES.new(temp_login_req_key, AES.MODE_GCM, nonce=nonce, mac_len=self.mac_len)
		AE.update(msg_hdr)
		encrypted_msg_payload, mac = AE.encrypt_and_digest(msg_payload)

		# encrypt temporary AES key
		enc_aes_key = enc_rsa(temp_login_req_key)

		# DEBUG
		if self.DEBUG:
			print('MTP message to send (' + str(msg_size) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('BDY (' + str(len(msg_payload)) + '): ')
			print(msg_payload.hex())
			print('------------------------------------------')
		# DEBUG

		# try to send
		try:
			self.send_bytes(msg_hdr + encrypted_msg_payload + mac + enc_aes_key)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to send message to peer --> ' + e.err_msg)

		self.msg_sqn += 1

	# -----------------------------------------------------------------------------------------
	# RSA Key Pair Generation for sending/recieving login requests/responses
	# -----------------------------------------------------------------------------------------

	# loads the server's public key from the file `pubkey.pem` residing in the current directory
	def load_publickey():
		pubkeyfile = 'pubkey.pem'
		with open(pubkeyfile, 'rb') as f:
			pubkeystr = f.read()
		try:
			return RSA.import_key(pubkeystr)
		except ValueError:
			print('Error: Cannot import public key from file ' + pubkeyfile)
			sys.exit(1)

	# loads the server's private key from the file `keypair.pem` residing in the current directory
	# TODO: generate a new keypair.pem file that is not password protected
	def load_keypair():
		privkeyfile = 'keypair.pem'
		passphrase = getpass.getpass('Enter a passphrase to decode the saved private key: ')
		with open(privkeyfile, 'rb') as f:
			keypairstr = f.read()
		try:
			return RSA.import_key(keypairstr, passphrase=passphrase)
		except ValueError:
			print('Error: Cannot import private key from file ' + privkeyfile)
			sys.exit(1)

	# encrypts and returns the temporary 32-byte AES key used for encrypting the login request using server's public key
	# TODO: Add try-catch blocks for if file is not in current directory
	def enc_rsa(self, temp_AES_key):
		# load the public key from the public key file and create an RSA cipher object
		pubkey = load_publickey()
		RSAcipher = PKCS1_OAEP.new(pubkey)

		# encrypt the AES key with the RSA cipher
		encaeskey = RSAcipher.encrypt(temp_AES_key)

		return encaeskey

	# decrypts and returns the RSA-encrypted AES key sent as part of the client's login request using the server's private key
	# TODO: Add try-catch blocks for if file is not in current directory
	def dec_rsa(self, encaeskey):

		# load the private key from the private key file and create the RSA cipher object
		keypair = load_keypair()
		RSAcipher = PKCS1_OAEP.new(keypair)

		# decrypt the AES key and create the AES cipher object
		decaeskey = RSAcipher.decrypt(encsymkey)

		return decaeskey
