#!/usr/bin/env python3

"""
Author: bashis <mcw noemail eu> 2019-2021
Subject: Dahua JSON Debug Console

[Updates]

March 2021:
Misc bug fixes and tuning for performance of self.P2P() 
DHIP artifact: Removed ["magic":"0x1234"]

January 2021 (Major rewrite):
1.	Implemented 'multicall' - big timesaver (!) (not 100% consistent usage for now, but working good as it is)
2.	'SendCall()' wrapper around 'self.P2P()'. self.P2P() should not be used directly (unless you want raw data).
3.	'console' Multiple simultaneous connections to devices, easy switching between active Console
4.	'password manager', create/change Dahua hash and connection details for devices, saved in 'dhConsole.json'
	- No fancy own encryption/decryption, we simply use the Dahua 'one way' format to save and pass on hashes.
	- ./Dahua-JSON-Debug-Console-v2.py --rhost <RHOST> --proto <PROTO> --rport <RPORT> --auth <USERNAME>:<PASSWORD> --save
5.	Events/Alarm, scanning config and subscribing on all found events/alarm
	- Listen for incoming event traffic on UDP from instances, accepting external TCP connections for relay of event traffic (only on 127.0.0.1)
	- The listening UDP socket for incoming are literally directly connected to outgoing TCP socket, for speedy reasons.
	- Meaning that output is unsorted, so the JSON needs to be fixed. Check fix_json() for details.
	- Listen for some events internally to give some info, using like 'reboot' to automatically restart connection
	- Added sending IP to JSON event to easily see where it came from
	- Simple 'eventviewer' with: --eventviewer
6.	'network wifi', WiFi scan/connect/enable/disable/reset
	- TODO: Should use events for some status updates
7.	'diag/pcap', Interim debug functions (pcap/NFS/logredirect) Note: Seems only to work with NVR
8.	'rdiscover/ldiscover', remote/local discovery of devices (ldiscover support both DHIP and DVRIP)
9.	Consistent way to write and handle 'Usage'
10.	Continue to Console even if console.attach fails (NVR)
	- Looks like to me that the thread is locked and do not accept any attach
11.	The 'fuzz()' function is an first attempt to fuzzing the '<method>.factory.instance' w/ potential '<method>.attach' to map needed params
	- Not really accurate for now, but can still give an hint what's required
	- Handle only one params for now, should handle two or more as well.
12.	'debug' various internal debug commands
And much more...

[For testing internal events]
$ cat exit.json
{"callback": 32380128, "id": 12, "method": "client.notifyEventStream", "params": {"SID": 513, "eventList": [{"Action": "Start", "Code": "Exit", "Data": {"LocaleTime": "2000-01-01 00:18:53", "UTC": 946657133.0}, "Index": 0}]}, "session": 32218112, "ipAddr": "192.168.57.21"}
$ cat exit.json | ncat -u 127.0.0.1 43210
[!] [2000-01-01 00:18:53 (192.168.57.21) ] Exit App

$ cat shutdown.json
{"callback": 52762696, "id": 12, "method": "client.notifyEventStream", "params": {"SID": 513, "eventList": [{"Action": "Start", "Code": "ShutDown", "Data": {"LocaleTime": "2000-01-01 00:07:13", "UTC": 946656433.0}, "Index": 0}]}, "session": 52568320, "ipAddr": "192.168.57.21"}
$ cat shutdown.json | ncat -u 127.0.0.1 43210
[!] [2000-01-01 00:07:13 (192.168.57.21) ] ShutDown App

$ cat reboot.json
{"callback": 32614288, "id": 12, "method": "client.notifyEventStream", "params": {"SID": 513, "eventList": [{"Action": "Start", "Code": "Reboot", "Data": {"LocaleTime": "2021-01-02 12:53:12", "UTC": 1609563192.0}, "Index": 0}]}, "session": 32468992, "ipAddr": "192.168.57.21"}
$ cat reboot.json | ncat -u 127.0.0.1 43210

[!] [2021-01-02 12:53:12 (192.168.57.21) ] Reboot
[!] dh0: IPC-HDxxxxxx-W (192.168.57.21)
[*] Closed connection to 192.168.57.21 port 37777
[*] Scheduling reconnect to 192.168.57.21
[+] Successful instance termination of IPC-HDxxxxxx-W (192.168.57.21)
[+] Opening connection to 192.168.57.21 on port 37777: Done
[+] Dahua JSON Console: Success
[+] Login: Success
[...]

[TODO]
Clean/narrow 'Exception's better
HTTP/HTTPS proxy

[BUGS]
Plenty fixed (and for sure new introduced)

[Note]
Even if 'service methods' shows up in lists, do _not_ automatically mean that the actual code exist.
- I.e. {"code":268632064,"message":"Component error: interface not found!"}

March 2020:
1. DVRIP SessionID bug: "method": "snapManager.listMethod".
2. Renamed 'ssh' to 'sshd', 'ssh' already used in some FW.

February 2020:
1. Added option 'setDebug', Should start produce output from Debug Console in VTO/VTH
2. Added '--discover', Multicast search of devices or direct probe (--rhost 192.168.57.20) of device via UDP/37810
3. Added '--dump {config,service}' for dumping config or services on remote host w/o entering Debug Console

January 2020:
1. Ported to Python 3
2. Fixed some bugs and code adjustment
3. Added support for DVRIP (TCP/37777) [Note: Some JSON commands that working with DHIP return nothing with DVRIP]
4. encode/decode in latin-1, we might need untouched chars between 0x00 - 0xff
5. Better 'debug' with hexdump as option

"""

import sys
import json
import ndjson	# pip3 install ndjson
import argparse
import copy
import _thread	
import inspect
import resource
import os.path
from os import path
import select, socket, queue

from json.decoder import JSONDecodeError

from Crypto.PublicKey import RSA # pip3 install pycryptodome
from OpenSSL import crypto # pip3 install pyopenssl
from pwn import *	# pip3 install pwntools (https://github.com/Gallopsled/pwntools)

global debug

# For Dahua DES/3DES
ENCRYPT = 0x00
DECRYPT = 0x01

# Colours
RED = '\033[31m'
GREEN = '\033[32m'
YELLOW = '\033[33m'
BLUE = '\033[34m'
WHITE = '\033[37m'

LRED = '\033[91m'
LGREEN = '\033[92m'
LYELLOW = '\033[93m'
LBLUE = '\033[94m'
LWHITE = '\033[97m'

EventInServerPort = 43210	# UDP listener port, receiving events
EventOutServerPort = 43211	# TCP listener port, delivery of events
keepAliveTimeOut = 5

def color(text,color):
	return "{}{}\033[0m".format(color,text)

#
# JSON data we will receive from events is an mess, need to sort out that before loading JSON to a list
# input: unsorted JSON
# return: sorted JSON in a list
#
def fix_json(mess):
	data = []
	start = 0
	result = ''

	for check in range(0,len(mess)):
		if mess[check] == '{':
			result += mess[check]
			start += 1
		elif start:
			result += mess[check]
			if mess[check] == '}':
				start -= 1
		if not start:
			try:
				if len(result):
					data.append(json.loads(result))
			except JSONDecodeError as e:
				log.warning('fix_json: {}'.format(e))
				pass
			result = ''
	if start:
		log.warning('fix_json: not complete')
	return data


#
# DVRIP have different codes in their protocols
#
def DahuaProto(proto):

	proto = binascii.b2a_hex(proto.encode('latin-1')).decode('latin-1')

	headers = [
		'f600',	# JSON
		'a005', # DVRIP login Send Login Details
		'a001', # DVRIP Send Request Realm
		'a000', # 3DES Login

		'b000', # DVRIP Recv
		'b001', # DVRIP Recv

		'a301', # DVRIP Discover Request
		'b300', # DVRIP Discover Response
	]

	if proto[:4] in headers:
		return True

	return False

#
# print help function
#
def helpMsg(data):

	return '\033[92m[\033[91m{}\033[92m]\033[0m\n'.format(data)

def helpAll(msg, Usage):
	"""
	Examples:
	#
	# Supported format
	#

	Usage = {
		"key0":"(value 0)",
		"key1":"(value 1)",
		"key2":"(value 2)",
		"key3":"(value 3)"
	}

	Usage = {
		"key0":"(value 0)",
		"key1":{
			"subkey0":"(value 0)",
			"subkey1":"(value 1)"
		},
		"key2":"(value 2)",
		"key3":"(value 3)"
	}

	Usage = {
		"key0":{
			"subkey0":"(value 0)",
			"subkey1":"(value 1)",
			"subkey2":"(value 2)"
		},
		"key1":{
			"subkey0":"(value 0)",
			"subkey1":"(value 1)"
		}
	}

	# One same line for all Usage()
	log.info('{}'.format(helpAll(msg=msg,Usage=Usage)))
	return True


	"""
	if msg.find('-h'):
		msg = msg.strip('-h')
	cmd = msg.split()

	try:
		data = '{}'.format(helpMsg('Usage'))

		for key in Usage if not len(cmd) > 1 else Usage.get(cmd[1]) if isinstance(Usage.get(cmd[1]),dict) else {cmd[1]}:

			if isinstance(Usage.get(key),dict):
				for subkey in Usage.get(key):
					data += '{} {} {} {}\n'.format(cmd[0], key, subkey, Usage.get(key).get(subkey,'(1 Not defined)'))

			elif isinstance(Usage.get(key) if not len(cmd) > 1 else key,str):
				data += '{} {} {}\n'.format(
					cmd[0],
					'{} {}'.format(cmd[1],key) if len(cmd) > 1 else key,
					Usage.get(key,'(Not defined: {})'.format(key)) if len(cmd) == 1 else Usage.get(cmd[1]).get(key,'(Not defined: {})'.format(key))
					)
			else:
				print('[else]')
				print(type(key),key)

		return data
	except AttributeError as e:
		print('error',e)


#############################################################################################################
#
# Dahua HASH / pwd Manager functions
#
#############################################################################################################

class pwdManager:

	def __init__(self, rhost=None, auth=None, login=None):

		self.gen1 = False
		self.gen2 = False
		self.login = login

		self.rhost = rhost
		self.auth = auth

	def DVRIP(self,query_args):

		proto = query_args.get('proto')

		if not self.auth:
			data = self.GetHost(self.rhost,hashes=True)
			if args.proto == '3des':
				self.login.failure(color('3DES: You need to use --auth <username>:<password>',RED))
				return False

			if not data:
				self.login.failure(color('You need to use --auth <username>:<password> [--save]',RED))
				return False

		if self.auth:
			USER_NAME = self.auth.split(':')[0]
			PASSWORD = self.auth.split(':')[1]


		if proto == '3des':
			data = {
				"username":self.Dahua_Gen0_hash(USER_NAME,ENCRYPT),
				"password":self.Dahua_Gen0_hash(PASSWORD,ENCRYPT)
			}

		elif proto == 'dvrip':

			if not query_args.get('random'):
				self.login.failure(color('Realm [random]',RED))
				return False

			REALM = query_args.get('realm')
			RANDOM = query_args.get('random')

			if not self.auth:
				data = self.GetHost(self.rhost,REALM)
				if not data:
					self.login.failure(color('You need to use --auth <username>:<password> [--save]',RED))
					return False
				USER_NAME = data.get('username')


			#
			# Login request
			#

			HASH = USER_NAME + '&&' + self.Dahua_Gen2_md5_hash(RANDOM, REALM, USER_NAME, PASSWORD if self.auth else None) + self.Dahua_DVRIP_md5_hash(RANDOM, USER_NAME, PASSWORD if self.auth else None)

			data = {
				"hash":HASH
			}

		return data

	def DHIP(self, query_args):

#		FakeIPaddr = '(null)'			# WebGUI: mask our real IP
#		FakeIPaddr = '192.168.57.1'
		FakeIPaddr = '127.0.0.1'
		clientType = ''				# WebGUI: We do not show up in logs or online users
#		clientType = 'Web3.0'			# Web3.0 / Dahua3.0 / CGI
		loginType = 'Direct'
		authorityType = 'Default'
		authorityInfo = ''
		passwordType = 'Default'


		if not self.auth :
			data = self.GetHost(self.rhost,hashes=True)
			if not data:
				self.login.failure(color('You need to use --auth <username>:<password> [--save]',RED))
				return False
			USER_NAME = data.get('username')
		else:
			USER_NAME = self.auth.split(':')[0]
			PASSWORD = self.auth.split(':')[1]

		if query_args.get('method') == 'global.login':

			params = {
				"clientType":clientType,
				"ipAddr":FakeIPaddr,
				"loginType":loginType,
				"password":"",
				"userName":USER_NAME,
				"Encryption":"None",
				}

			return params

		elif query_args.get('error').get('code') == 268632079: # DHIP REALM

			query_args = query_args.get('params')

			RANDOM = query_args.get('random')
			REALM = query_args.get('realm')
			ENCRYPTION = query_args.get('encryption')
			AUTHORIZATION = query_args.get('authorization')	# Not known usage, unique for each device but not random
			MAC = query_args.get('mac')

			if not self.auth:
				# We just checking RandSalt from REALM here
				data = self.GetHost(self.rhost,REALM)
				if not data:
					self.login.failure(color('You need to use --auth <username>:<password> [--save]',RED))
					return False
				if not (ENCRYPTION == 'Default' or ENCRYPTION == 'OldDigest'):
					self.login.failure(color('Encryption: "{}", You need to use --auth <username>:<password>'.format(ENCRYPTION),RED))
					return False


			if ENCRYPTION == 'Default':
				HASH = self.Dahua_Gen2_md5_hash(RANDOM, REALM, USER_NAME, PASSWORD if self.auth else None)
			elif ENCRYPTION == 'OldDigest':
				HASH = self.gen1 if self.gen1 else self.Dahua_Gen1_hash(PASSWORD)
			elif ENCRYPTION == 'Basic':
				HASH = self.Basic(USER_NAME,PASSWORD)
			elif ENCRYPTION == 'Plain':
				HASH = PASSWORD
			else:
				log.fail('Unknown encryption: {}'.format(ENCRYPTION))
				return False

			passwordType = {
				"Plain":"Plain",
				"Basic":"Basic",
				"OldDigest":"OldDigest",
				"Default":"Default",
				"2DCode":"2DCode"
			}

			authorityType = {
				"Plain":"Plain",
				"Basic":"Basic",
				"OldDigest":"Default",
#				"OldDigest":"OldDigest",
				"Default":"Default",
				"2DCode":"2DCode"
			}

			params = {
				"userName":USER_NAME,
				"password":HASH,
				"clientType":clientType,
				"ipAddr":FakeIPaddr,	
				"loginType":loginType,
				"authorityInfo":authorityInfo,
				"authorityType":authorityType.get(ENCRYPTION),
				"passwordType":passwordType.get(ENCRYPTION),
				}

			return params
		return

	def ReadHosts(self):

		try:
			with open('dhConsole.json') as file:
				return json.load(file)
		except Exception as e:
			log.failure(color('ReadHosts: {}'.format(e),RED))
			return False

	def WriteHosts(self,data):

		try:
			with open('dhConsole.json','w') as file:
				json.dump(data,file)
				log.success(color('Host saved successfully',GREEN))
				return True
		except Exception as e:
			log.failure(color('WriteHosts: {}'.format(e),RED))
			return False

	def SaveHost(self,rhost,rport,proto,auth,realm):

		data = self.ReadHosts()
		if not data:
			data = []

		if not self.Get(rhost):
			log.info('Adding new host "{}"'.format(rhost))
			data.append({
				"ipAddr":rhost,
				"port":rport,
				"proto":proto,
				"username":auth.split(':')[0],
				"password":{
					"gen1":self.Dahua_Gen1_hash(auth.split(':')[1]),
					"gen2":hashlib.md5((auth.split(':')[0] + ':' + realm + ':' + auth.split(':')[1]).encode('latin-1')).hexdigest().upper(),
					"RandSalt":realm.split()[2]
				},
				"events":True,
				})
		else:
			log.info('Updating host "{}"'.format(rhost))
			for host in range(0,len(data)):
				if rhost == data[host].get('ipAddr'):
					break
			data[host].update({
				"ipAddr":rhost,
				"port":rport,
				"proto":proto,
				"username":auth.split(':')[0],
				"password":{
					"gen1":self.Dahua_Gen1_hash(auth.split(':')[1]),
					"gen2":hashlib.md5((auth.split(':')[0] + ':' + realm + ':' + auth.split(':')[1]).encode('latin-1')).hexdigest().upper(),
					"RandSalt":realm.split()[2]
				},
				"events":True,
				})

		if not self.WriteHosts(data):
			return False

		return True

	def GetHost(self,ipAddr=False,realm=False,hashes=False):

		data = self.Get(ipAddr)

		if not data:
			log.failure('Host "{}" do not exist'.format(ipAddr))
			return False

		if realm:
			RandSalt = realm.split()[2]
			if not data.get('password').get('RandSalt') == RandSalt:
				log.failure(color('RandSalt differs, current hash does not work anymore!',LRED))
				return False

		if hashes:
			self.gen1 = data.get('password').get('gen1')
			self.gen2 = data.get('password').get('gen2')
			if not self.gen1 or not self.gen2:
				log.failure('No available hashes!')
				return False

		return data

	def Get(self,ipAddr=False):


		data = self.ReadHosts()
		if not data:
			return False
		if not ipAddr:
			return data

		if ipAddr:
			for host in range(0,len(data)):
				if ipAddr == data[host].get('ipAddr'):
					tmp = True
					break
				else:
					tmp = False

			return data[host] if tmp else False


	#
	# The DES/3DES code in the bottom of this script.
	# 
	def Dahua_Gen0_hash(self,data, mode):

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
			self.deshash = data
		else:
			data = k.decrypt(data)
			data = data.decode('latin-1').strip('\x00') # Strip all 0x00 padding

		return data

	#
	# From: https://github.com/haicen/DahuaHashCreator/blob/master/DahuaHash.py
	#
	#
	def compressor(self,in_var, out):
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
			
	def Dahua_Gen1_hash(self,passw):
	#	if len(passw)>6:
	#		debug("Warning: password is more than 6 characters. Hash may be incorrect")
		m = hashlib.md5()
		m.update(passw.encode("latin-1"))
		
		s=m.digest()
		crypt=[]
		for b in s:
			crypt.append(b)

		out2=['']*8
		self.compressor(crypt,out2)
		data=''.join([chr(a) for a in out2])

		return data
	#
	# END 
	#

	def Basic(self,username, password):

		return b64e(username.encode('latin-1') + b':' + password.encode('latin-1'))

	#
	# Dahua DVRIP random MD5 password hash
	#
	def Dahua_DVRIP_md5_hash(self,Dahua_random, username, password):

		RANDOM_HASH = hashlib.md5((username + ':' + Dahua_random + ':' + self.gen1 if self.gen1 else self.Dahua_Gen1_hash(password)).encode('latin-1')).hexdigest().upper()

		return RANDOM_HASH

	#
	# Dahua random MD5 password hash
	#
	def Dahua_Gen2_md5_hash(self,Dahua_random, Dahua_realm, username, password):

		PWDDB_HASH = self.gen2 if self.gen2 else hashlib.md5((username + ':' + Dahua_realm + ':' + password).encode('latin-1')).hexdigest().upper()
		PASS = (username + ':' + Dahua_random + ':' + PWDDB_HASH).encode('latin-1')
		RANDOM_HASH = hashlib.md5(PASS).hexdigest().upper()

		return RANDOM_HASH

#############################################################################################################
#
# Simple Event Viewer
#
#############################################################################################################

class SimpleEventViewer:

	def __init__(self):
		log.success("[Simple Event Viewer]")

		self.EventConnect()

	def EventConnect(self):

		try:
			self.remote = remote('127.0.0.1', EventOutServerPort, ssl=False, timeout=5)

		except (SystemExit) as e:
			log.warning("[Simple Event Viewer]: {}".format(e))
			if self.remote.connected():
				self.remote.close()
			return False

		self.EventReceive()
		return False

	def EventReceive(self):

		try:
			while True:
				data = ''

				while True:
					tmp = len(data)
					data += self.remote.recv(numb=8192,timeout=1).decode('latin-1')
					if tmp == len(data):
						break

				if len(data):
					self.EventViewer(data)

		except (Exception, KeyboardInterrupt, SystemExit) as e:
			log.warning("[Simple Event Viewer]: {}".format(e))
			if self.remote.connected():
				self.remote.close()
			return False

	def EventViewer(self,data):

		# fix the JSON mess
		data = fix_json(data)
		if not len(data):
			log.warning('[Simple Event Viewer]: callback data invalid!\n{}'.format(callback))
			return False

		for events in data:
			log.info('[Event From]: {}\n{}'.format(color(events.get('ipAddr'),GREEN), events))

	#############################################################################################################
	#
	# main init and loop for console I/O
	#
	# If multiple Consoles is attached to one device, all attached Consoles will receive same output from device
	#
	#############################################################################################################

class DebugConsole:

	def __init__(self):

		self.udp_server = False
		self.tcp_server = False
		self.events = args.events

		if args.dump or args.test:
			return self.Dump()

		self.MainConsole()

	#
	# Will terminate and restart instances in case of some failure
	#
	def TerminateDaemons(self,threadName):

		time.sleep(1)
		if not self.udp_server:
			return False

		status = log.progress(color("Terminate Daemons thread",YELLOW))
		status.success(color("Started",GREEN))

		daemon = False

		while True:
			time.sleep(10)
			for session in self.dhConsole:
				instance = self.dhConsole.get(session).get('instance')
				if instance.terminate and not instance.remote.connected():
					ipAddr = self.dhConsole.get(session).get('ipAddr')
					daemon = True
					break

			try:
				if daemon:
					self.dhConsole.pop(session)
					if self.dh == instance:
						for session in self.dhConsole:
							self.dh = self.dhConsole.get(session).get('instance')
							break
					del instance
					daemon = False
					_thread.start_new_thread(self.RestartConnection,("RestartConnection",ipAddr,))
					if not len(self.dhConsole):
						log.error('Terminate Daemons: No other active sessions')
						return False

			except (Exception, PwnlibException) as e:
				status.failure('{}'.format(e))
				return False

	#
	# Will handle all incoming event traffic on UDP, accepting connections from TCP to relay event traffic
	# - The receiving UDP socket is literally connected to sending TCP socket
	# - Will also send to internal event handler, to catch some events
	# - Since it's unsorted JSON from multiple instanses, the JSON needs to be fixed with 'fix_json()'
	#
	# Good info
	# https://steelkiwi.com/blog/working-tcp-sockets/
	def EventInOutServer(self,threadName):

		status = log.progress(color("UDP/TCP EventInOutServer listener thread",YELLOW))

		try:
			self.tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self.tcp_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			self.tcp_server.setblocking(0)
			self.tcp_server.bind(('127.0.0.1', EventOutServerPort))
			self.tcp_server.listen(10)

			self.udp_server = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
			self.udp_server.bind(('127.0.0.1', EventInServerPort))

		except OSError as e:
			self.udp_server = False
			self.tcp_server = False
			status.failure(color("{}".format(e),RED))
			return False

		inputs = [self.tcp_server,self.udp_server]
		outputs = []
		message_queues = {}

		try:
			status.success(color("Started",GREEN))

			while True:

				readable, writable, exceptional = select.select(
					inputs, outputs, inputs)

				for s in readable:
					if s is self.tcp_server:
						connection, client_address = s.accept()
#						log.info('Connection: {}'.format(client_address))
						connection.setblocking(0)
						inputs.append(connection)
						message_queues[connection] = queue.Queue()
					else:
						if s is not self.udp_server:
							data = s.recv(1024)
							if s not in outputs:
								outputs.append(s)
							if not data:
								if s in outputs:
									outputs.remove(s)
								inputs.remove(s)
								s.close()
								del message_queues[s]

						else:
							data, address = self.udp_server.recvfrom(8192)
#							log.info('Incoming data from: {}'.format(address))
							if len(data) == 8192:
								log.warning('EventInOutServer: LEN == 8192')
								print(data)
							if data:
								self.InternalEventManager(data.decode('latin-1'))
								for tmp in message_queues:
									message_queues[tmp].put(data)
									if tmp not in outputs:
										outputs.append(tmp)

				for s in writable:
					try:
						next_msg = message_queues[s].get_nowait()
					except queue.Empty:
						outputs.remove(s)
					else:
						s.send(next_msg)

				for s in exceptional:
					if s in inputs:
						inputs.remove(s)
					if s in outputs:
						outputs.remove(s)
					s.close()
					del message_queues[s]



		except (Exception) as e:
			status.failure('{}'.format(e))
			return False
	#
	# JSON fixing part, then feed 'LocalEventHandler()'
	#
	def InternalEventManager(self,data):

		try:
			events = fix_json(data)
			for event in events:
				self.LocalEventHandler(event)
		except (Exception) as e:
			log.failure('InternalEventManager: {}'.format(e))
	#
	# Local event handler
	#
	def LocalEventHandler(self,data):

		try:
			ipAddr = data.get('ipAddr')
			eventList = data.get('params').get('eventList')

			for events in eventList:
				if events.get('Action') == 'Start':
					#
					# Reboot event, remote device is already rebooting and we cannot make clean exit, so just close instance and reschedule connection
					#
					if events.get('Code') == 'Reboot':
						log.warning('[{} ({}) ] {}'.format(
							color(events.get('Data').get('LocaleTime'),LYELLOW),
							color(ipAddr,GREEN),
							color('Reboot',RED),
							))
						tmp = False

						for session in self.dhConsole:
							if self.dhConsole.get(session).get('ipAddr') == ipAddr:
								log.warning("{}: {} ({})".format(
								session,
								self.dhConsole.get(session).get('device'),
								self.dhConsole.get(session).get('ipAddr'),
								))

								tmp = self.dhConsole.get(session).get('instance') 
								tmp.terminate = True
								tmp.logout()
								break
						if tmp:
							if tmp == self.dh:
								del self.dh
								self.dhConsole.pop(session)

								if len(self.dhConsole):
									for session in self.dhConsole:
										self.dh = self.dhConsole.get(session).get('instance')
										break
							else:
								del tmp
								self.dhConsole.pop(session)

						_thread.start_new_thread(self.RestartConnection,("RestartConnection",ipAddr,))

					elif events.get('Code') == 'Exit':

						log.warning('[{} ({}) ] {}'.format(
							color(events.get('Data').get('LocaleTime'),YELLOW),
							color(ipAddr,GREEN),
							color('Exit App',RED),
							))
					elif events.get('Code') == 'ShutDown':

						log.warning('[{} ({}) ] {}'.format(
							color(events.get('Data').get('LocaleTime'),YELLOW),
							color(ipAddr,GREEN),
							color('ShutDown App',RED),
							))
					# VTO
					elif events.get('Code') == 'AlarmLocal':

						log.warning('[{} ({}) ] {}'.format(
							color(events.get('Data').get('LocaleTime'),YELLOW),
							color(ipAddr,GREEN),
							color('AlarmLocal [Start]',RED),
							))
					# VTO
					elif events.get('Code') == 'ProfileAlarmTransmit':
						log.warning('[{} ({}) ] {}'.format(
							color(events.get('Data').get('LocaleTime'),YELLOW),
							color(ipAddr,GREEN),
							color('ProfileAlarmTransmit [Start]\nAlarmType: {}, DevSrcType: {}, SenseMethod: {}, UserID: {}'.format(
								events.get('Data').get('AlarmType'),
								events.get('Data').get('DevSrcType'),
								events.get('Data').get('SenseMethod'),
								events.get('Data').get('UserID'),
								),RED),
							))

				elif events.get('Action') == 'Stop':

					# VTO
					if events.get('Code') == 'AlarmLocal':

						log.warning('[{} ({}) ] {}'.format(
							color(events.get('Data').get('LocaleTime'),YELLOW),
							color(ipAddr,GREEN),
							color('AlarmLocal [Stop]',GREEN),
							))

					# VTO
					elif events.get('Code') == 'ProfileAlarmTransmit':
						log.warning('[{} ({}) ] {}'.format(
							color(events.get('Data').get('LocaleTime'),YELLOW),
							color(ipAddr,GREEN),
							color('ProfileAlarmTransmit [Stop]\nAlarmType: {}, DevSrcType: {}, SenseMethod: {}, UserID: {}'.format(
								events.get('Data').get('AlarmType'),
								events.get('Data').get('DevSrcType'),
								events.get('Data').get('SenseMethod'),
								events.get('Data').get('UserID'),
								),GREEN),
							))

				elif events.get('Action') == 'Pulse':

					if events.get('Code') == 'SafetyAbnormal':
						log.warning('[{} ({}) ] {}'.format(
							color(events.get('Data').get('AbnormalTime') if events.get('Data').get('AbnormalTime') else events.get('Data').get('LocaleTime'),YELLOW),
							color(ipAddr,GREEN),
							color('{} {}'.format(
								events.get('Data').get('ExceptionType'),
								events.get('Data').get('Address')
								),RED),
							))

					elif events.get('Code') == 'LoginFailure':
						log.warning('[{} ({}) ] {}'.format(
							color(events.get('Data').get('LocaleTime'),YELLOW),
							color(ipAddr,GREEN),
							color('Login Failure: {} {} ({})'.format(
								events.get('Data').get('Name'),
								events.get('Data').get('Address'),
								events.get('Data').get('Type')
								),RED),
							))

					elif events.get('Code') == 'RemoteIPModified':
						log.warning('[{} ({}) ] {}\n{}'.format(
							color(events.get('Data').get('LocaleTime'),YELLOW),
							color(ipAddr,GREEN),
							color('DHDiscover.setConfig',YELLOW),
							events.get('Data'),
							))

					elif events.get('Code') == 'Reset':
						log.warning('[{} ({}) ] {}'.format(
							color(events.get('Data').get('LocaleTime'),YELLOW),
							color(ipAddr,GREEN),
							color('Factory default reset',RED),
							))

					# VTH
					elif events.get('Code') == 'InfoTip':
						log.warning('[{} ({}) ] {}'.format(
							color(events.get('Data').get('LocaleTime'),YELLOW),
							color(ipAddr,GREEN),
							color('InfoTip',YELLOW),
							))
					# VTH
					elif events.get('Code') == 'KeepLightOn':
						log.warning('[{} ({}) ] {}'.format(
							color(events.get('Data').get('LocaleTime'),YELLOW),
							color(ipAddr,GREEN),
							color('KeepLightOn: {}'.format(events.get('Data').get('Status')),YELLOW),
							))
					# VTH
					elif events.get('Code') == 'ScreenOff':
						log.warning('[{} ({}) ] {}'.format(
							color(events.get('Data').get('LocaleTime'),YELLOW),
							color(ipAddr,GREEN),
							color('ScreenOff',YELLOW),
							))
					# VTH
					elif events.get('Code') == 'VthAlarm':
						log.warning('[{} ({}) ] {}'.format(
							color(events.get('Data').get('LocaleTime'),YELLOW),
							color(ipAddr,GREEN),
							color('VTH Alarm',RED),
							))


		except (Exception) as e:
			log.failure('LocalEventHandler: {}'.format(e))
			pass
	#
	# Handle restart of connections, trying every 30sec for 10 times, if no success, stop trying
	#
	def RestartConnection(self,threadName,ipAddr):

		log.info('Scheduling reconnect to {}'.format(ipAddr))

		Host = pwdManager()
		data = Host.Get(ipAddr)

		times = 0

		while True:
			time.sleep(30)
			if not self.ConnectRhost(
				rhost=data.get('ipAddr'),
				rport=data.get('port'),
				proto=data.get('proto'),
				username=data.get('username'),
				password=None,
				events=data.get('events'),
				ssl=args.ssl,
				timeout=5):
				times += 1
			else:
				return True

			if times == 10:
				log.failure('See you in valhalla {}'.format(ipAddr))
				return False
	#
	# Handle the '--dump' options from command line
	#
	def Dump(self):

		self.dhConsole = {}
		self.dhConsoleNo = 0
		self.udp_server = False

		if not self.ConnectRhost(
			rhost=args.rhost,
			rport=args.rport,
			proto=args.proto,
			username=args.auth.split(':')[0] if args.auth else None,
			password=args.auth.split(':')[1] if args.auth else None,
			events=self.events,
			ssl=args.ssl,
			timeout=5):
			return None

		if args.test:
			self.dh.TEST('test')
			return None

		if args.dump =='config':
			self.dh.config_members("{} {}".format("config",args.dump_argv if args.dump_argv else "all"))
			self.dh.logout()
			return None
		elif args.dump == 'service':
			self.dh.listService("{} {}".format("service",args.dump_argv if args.dump_argv else "all"))
			self.dh.logout()
			return None
		elif args.dump == 'device':
			self.dh.GetRemoteInfo('device')
			self.dh.logout()
			return None
		elif args.dump == 'discover':
			self.dh.deviceDiscovery("{} {}".format("discover",args.dump_argv))
			self.dh.logout()
			return None
		elif args.dump == 'test':
			self.dh.TEST('test')
			self.dh.logout()
			return None
		elif args.dump == 'log':
			self.dh.dlog('test')
			self.dh.logout()
			return None
		else:
			log.error('No such dump: {}'.format(args.dump))
			return None

	#
	# Main console for instanses
	#
	def MainConsole(self):

		#
		# Additional Cmd list
		#
		cmd_list = {
		#
		# misc
		#
		'certificate':{
			'cmd':'self.dh.GetRemoteInfo("certificate")',
			'help':'Dump some information of remote certificate',
			},
		'config':{
			'cmd':'self.dh.config_members(msg)',
			'help':'remote config (-h for params)',
			},
		'console':{
			'cmd':'self.dahuaConsole(msg)',
			'help':'console instance handling (-h for params)',
			},
		'debug':{
			'cmd':'self.debugInstance(msg)',
			'help':'debug instance (-h for params)',
			},
		'device':{
			'cmd':'self.dh.GetRemoteInfo(msg)',
			'help':'Dump some information of remote device',
			},
		'dhp2p':{
			'cmd':'self.dh.GetRemoteInfo("dhp2p")',
			'help':'Dump some information of dhp2p',
			},
		'diag':{
			'cmd':'self.dh.InterimRemoteDiagnose(msg)',
			'help':'Interim Remote Diagnose (-h for params)',
			},
		'door':{
			'cmd':'self.dh.open_door(msg)',
			'help':'open door (-h for params)',
			},
		'events':{
			'cmd':'self.dh.eventManager(msg)',
			'help':'Subscribe on events from eventManager (-h for params)',
			},
		'fuzz':{
			'cmd':'self.dh.fuzzService(msg)',
			'help':'fuzz service methods (-h for params)',
			},
		'ldiscover':{
			'cmd':'self.dh.DHDiscover(msg)',
			'help':'Device Discovery from this script (-h for params)',
			},
		'log':{
			'cmd':'self.dh.dlog(msg)',
			'help':'Log stuff (-h for params)',
			},
		'network':{
			'cmd':'self.dh.netApp(msg)',
			'help':'Network stuff (-h for params)',
			},
		'memory':{
			'cmd':'log.info("Memory usage: {}".format(size(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)))',
			'help':'Used memeory of this script (-h for params)',
			},
		'pcap':{
			'cmd':'self.dh.NetworkSnifferManager(msg)',
			'help':'pcap in remote device (-h for params)',
			},
		'rdiscover':{
			'cmd':'self.dh.deviceDiscovery(msg)',
			'help':'Device Discovery from remote device (-h for params)',
			},
		'service':{
			'cmd':'self.dh.listService(msg)',
			'help':'List remote services and "methods" (-h for params)',
			},
		'sshd':{
			'cmd':'self.dh.telnetd_SSHD(msg)',
			'help':'Start / Stop (-h for params)',
			},
		'setDebug':{
			'cmd':'self.dh.setDebug(msg)',
			'help':'Should start produce output from Console in VTO/VTH',
			},
		'telnet':{
			'cmd':'self.dh.telnetd_SSHD(msg)',
			'help':'Start / Stop (-h for params)',
			},
		'test-config':{
			'cmd':'self.dh.newConfig(msg)',
			'help':'New config test (-h for params)',
			},
		'uboot':{
			'cmd':'self.dh.uBoot(msg)',
			'help':'U-Boot Environment Variables (-h for params)',
			},
		'"quit"':{
			'cmd':'self.dahuaConsole(msg)',
			'help':'"quit" active instance "quit all" to quit from all',
			},
		'"reboot"':{
			'cmd':'self.dahuaConsole(msg)',
			'help':'"reboot" active instance "reboot all" to reboot all',
			},
		'REBOOT':{
			'cmd':'self.dh.reboot(msg)',
			'help':'Try force reboot of remote',
			},
		'TEST':{
			'cmd':'self.dh.TEST(msg)',
			'help':'TEST function (-h for params)',
			},
		}

		self.dhConsole = {}
		self.dhConsoleNo = 0

		if not args.auth:
			Host = pwdManager()
			data = Host.GetHost()
			if not data:
				return False

		if self.events:
			_thread.start_new_thread(self.EventInOutServer,("EventInOutServer",))
			_thread.start_new_thread(self.TerminateDaemons,("TerminateDaemons",))

		#
		# Connect multiple pre-defined devices
		#
		if args.multihost and not (args.dump or args.test):

			for host in range(0,len(data)):
				if not self.ConnectRhost(
					rhost=data[host].get('ipAddr'),
					rport=data[host].get('port'),
					proto=data[host].get('proto'),
					username=data[host].get('username'),
					password=None,
					events=args.events if args.events else data[host].get('events'),
					ssl=args.ssl,
					timeout=5):
						pass
		#
		# Connect single device pre-defined/or w/ credentials from command line
		#
		else:
			if not self.ConnectRhost(
				rhost=args.rhost,
				rport=args.rport,
				proto=args.proto,
				username=args.auth.split(':')[0] if args.auth else None,
				password=args.auth.split(':')[1] if args.auth else None,
				events=self.events,
				ssl=args.ssl,
				timeout=5):
				return False
		#
		# Main Console loop
		#
		while True:
			try:
				self.prompt()
				msg = sys.stdin.readline().strip().decode('latin-1')
				if not self.dh or not self.dh.remote.connected():
					log.failure('No available instances')
					return False
				cmd = msg.split()

				if msg:
					if msg == 'shell' and not args.force:
						log.failure("[shell] will execute and hang the Console/Device (DoS)")
						log.failure("If you still want to try, run this script with --force")
						continue
					elif msg == 'exit' and not args.force:
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

					if self.dh.terminate:
						# console kill self.dh
						self.dahuaConsole('console kill self.dh')
						continue

					if msg == 'quit' or len(cmd) == 2 and cmd[0] == 'quit' and cmd[1] == 'all':

						if len(cmd) == 2 and cmd[1] == 'all':
							self.Quit(All=True)
							return True
						if not self.Quit(All=False,msg=msg):
							return False

					elif msg == 'shutdown' or msg == 'reboot' or len(cmd) == 2 and cmd[1] == 'all':

						if len(cmd) == 2 and cmd[1] == 'all':
							self.Quit(All=True,msg=msg)
							return True

						if not self.Quit(All=False,msg=msg):
							return False

					elif msg == 'help':
						self.dh.runCmd(msg)
						log.info("Local cmd:")
						for command in cmd_list:
							log.success("{}: {}".format(command,cmd_list[command]['help']))

					else:
						self.dh.runCmd(msg)
						if not self.dh.ConsoleAttach and not args.force:
							log.failure("Invalid command: 'help' for help")

			except KeyboardInterrupt as e:
				pass
	#
	# Quit from single device, or 'All'
	#
	def Quit(self,All=False,msg=None):

		if msg:
			cmd = msg.split()

		if All:
			while True:
				for session in self.dhConsole:
					log.warning("{}: {} ({})".format(
					session,
					self.dhConsole.get(session).get('device'),
					self.dhConsole.get(session).get('ipAddr'),
					))
					self.dh = self.dhConsole.get(session).get('instance')
					if msg and len(cmd) == 2 and cmd[1] == 'all':
						self.dh.cleanup()
						self.dh.runCmd(cmd[0])
						if not self.dh.ConsoleAttach and cmd[0] == 'reboot':
							self.dh.reboot(delay=2)
					self.dh.logout()
					self.dh.terminate = True
					break
				del self.dh
				self.dhConsole.pop(session)
				if not len(self.dhConsole):
					break
			if self.tcp_server:
				self.tcp_server.close()
			if self.udp_server:
				self.udp_server.close()
			return True
		else:
			for session in self.dhConsole:
				if self.dhConsole.get(session).get('instance') == self.dh:
					log.warning("{}: {} ({})".format(
					session,
					self.dhConsole.get(session).get('device'),
					self.dhConsole.get(session).get('ipAddr'),
					))
					self.dh.cleanup()
					self.dh.runCmd(msg)
					if not self.dh.ConsoleAttach and msg == 'reboot':
						self.dh.reboot(delay=2)
					self.dh.logout()
					self.dh.terminate = True
					self.dhConsole.pop(session)
					del self.dh
					break

			if not self.dhInstance():
				return False
			return True

	#
	# Show or connect one instance
	#
	def dhInstance(self,show=False):

		if not show:
			if not len(self.dhConsole):
				self.dh = False
				return False

			for session in self.dhConsole:
				self.dh = self.dhConsole.get(session).get('instance')
				break

		for session in self.dhConsole:
			log.info('Console: {}, Device: {} ({}) {} {}'.format(
				session,
				self.dhConsole.get(session).get('device'),
				self.dhConsole.get(session).get('ipAddr'),
				color('Active',GREEN) if self.dhConsole.get(session).get('instance') == self.dh else '',
				'{} {}'.format(
					color('(calls)'.format(self.dhConsole.get(session).get('instance').debug),YELLOW) if self.dhConsole.get(session).get('instance').debugCalls else '',
					color('(traffic: {})'.format(self.dhConsole.get(session).get('instance').debug),YELLOW) if self.dhConsole.get(session).get('instance').debug else '',
			)))
		return True
	#
	# Handling connection(s) to remote device
	#
	def ConnectRhost(self, rhost, rport, proto, username, password, events, ssl, timeout):

		util = Utility()
		# Check if RPORT is valid
		if not util.Port(rport):
			log.failure("Invalid RPORT - Choose between 1 and 65535")
			return False

		# Check if RHOST is valid IP or FQDN, get IP back
		rhost = util.Host(rhost)
		if not rhost:
			log.failure("Invalid RHOST")
			return False

		for session in self.dhConsole:
			if self.dhConsole.get(session).get('ipAddr') == rhost:
				log.warning('Already connected to {}'.format(rhost))
				return False

		time.sleep(1)	# Needed for get 'self.udp_server' set

		dh = Dahua_Functions(
			rhost=rhost,
			rport=rport,
			proto=proto,
			username=username,
			password=password,
			events=events,
			ssl=ssl,
			timeout=timeout,
			udp_server=self.udp_server
			)
		if not dh.Connect():
			return False

		self.dh = dh
		self.dhConsole.update({
			'dh' + str(self.dhConsoleNo):{
				'instance':self.dh,
				'ipAddr':rhost,
				'proto':proto,
				'port':rport,
				'device':self.dh.DeviceType,
			}
		})
		self.dhConsoleNo += 1

		return True
	#
	# Prompt
	#
	def prompt(self):
		PromptText = "\033[92m[\033[91mConsole\033[92m]\033[0m# "
		sys.stdout.write(PromptText)
		sys.stdout.flush()

	#
	# Handling connection/kill of instance from main Console
	#
	def dahuaConsole(self,msg):

		cmd = msg.split()

		Usage = {
			"conn":{
				"all":"(connect all pre-defined devices)",
				"<username>":"<password> <ipAddr> [[<port>] | [ <dvrip | dhip | 3des> [<port>]]",
				"<ipAddr>":"(connect pre-defined device <ipAddr>)"
			},
			"kill":{
				"dh<#>":"(kill instance dh<#>)"
			},
			"dh<#>":"(switch active console. e.g. 'console dh0')"
		}

		if len(cmd) == 2 and cmd[1] == '-h':

			log.info('{}'.format(helpAll(msg=msg, Usage=Usage)))
			return True

		elif len(cmd) == 3 and cmd[1] == 'kill':

			if len(cmd) == 2:
				log.info('{}'.format(helpAll(msg=msg, Usage=Usage)))
				return True
			try:
				tmp = self.dhConsole.get(cmd[2]).get('instance')
			except AttributeError as e:
				log.failure('Console ({}) do not exist'.format(cmd[2]))
				return False

			self.dhConsole.pop(cmd[2])

			tmp.terminate = True
			tmp.logout()

			del tmp

			if not self.dhInstance():
				return False
			return True

		elif len(cmd) >= 2 and cmd[1] == 'conn':

			if len(cmd) > 2  and cmd[2] == '-h':
				log.info('{}'.format(helpAll(msg=msg, Usage=Usage)))
				return False

			if len(cmd) == 2 or len(cmd) == 3:

				Host = pwdManager()

				if len(cmd) == 2:

					data = Host.GetHost()
					for host in range(0,len(data)):

						conn = next((session for session in self.dhConsole if data[host].get('ipAddr') == self.dhConsole.get(session).get('ipAddr')),None)
						log.info('{} {}'.format(data[host].get('ipAddr'),'Connected ({})'.format(color(conn,GREEN)) if conn else '') )

					return True

				if cmd[2] == 'all': # console conn all
					data = Host.GetHost()
					for host in range(0,len(data)):
						if not self.ConnectRhost(
							rhost=data[host].get('ipAddr'),
							rport=data[host].get('port'),
							proto=data[host].get('proto'),
							username=data[host].get('username'),
							password=None,
							events=args.events if args.events else data[host].get('events'),
							ssl=args.ssl,
							timeout=5):
								pass
					return True


				ipAddr = util.Host(cmd[2])

				if not ipAddr:
					log.failure('"{}" not valid ipAddr'.format(cmd[2]))
					return False

				data = Host.GetHost(ipAddr=ipAddr)

				if not self.ConnectRhost(
					rhost=data.get('ipAddr'),
					rport=data.get('port'),
					proto=data.get('proto'),
					username=data.get('username'),
					password=None,
					events=args.events if args.events else data.get('events'),
					ssl=args.ssl,
					timeout=5):
					return False

				if not self.dhInstance(show=True):
					return False
				return True

			elif len(cmd) == 4:
				return False
			elif len(cmd) >= 5 and not len(cmd) > 5:
				rhost = cmd[4]
				rport = cmd[5] if len(cmd) == 6  else 37777
				proto = 'dvrip'
			elif len(cmd) >= 6 and cmd[5] == 'dhip':
				rport = cmd[6] if len(cmd) == 7 else 5000
				proto = cmd[5]
			elif len(cmd) >= 6 and cmd[5] == 'dvrip' or cmd[5] == '3des':
				rport = cmd[6] if len(cmd) == 7 else 37777
				proto = cmd[5]
			else:
				log.info('{}'.format(helpAll(msg=msg, Usage=Usage)))
				return False

			if not self.ConnectRhost(
				rhost=cmd[4],
				rport=rport,
				proto=proto,
				username=cmd[2],
				password=cmd[3],
				events=self.events,
				ssl=args.ssl,
				timeout=5):
				return False

		elif len(cmd) == 2:

			if cmd[1] == '-h':
				log.info('{}'.format(helpAll(msg=msg,Usage=Usage)))
				return False

			try:
				self.dh = self.dhConsole.get(cmd[1]).get('instance')
			except AttributeError as e:
				log.failure("Console [{}] do not exist".format(cmd[1]))
				return

		if not self.dhInstance(show=True):
			return False
		return True


	#
	# Handle 'debug' command from main Console
	#
	def debugInstance(self,msg):

		cmd = msg.split()

		Usage = {
			"object":"(dict with info about attached services)",
			"loop":"(send a loop packet)",
			"instances":"(dict connection details of instances)",
			"calls":"<0|1> (debug internal calls)",
			"traffic":"(debug DHIP/DVRIP traffic)",
			"test":"test"
		}
		if not len(cmd) > 1:
			log.info('{}'.format(helpAll(msg=msg,Usage=Usage)))
			return

		if cmd[1] == 'object':
			self.dh.InstanceService(methodName="",listAll=True)

		elif cmd[1] == 'test':
			object_methods = [method_name for method_name in dir(self.dh)
				if callable(getattr(self.dh, method_name))]
			print(object_methods)

		elif cmd[1] == 'loop':
			self.dh.testLoop(json.dumps({"id":1337}))

		elif cmd[1] == 'instances':
			for dh in self.dhConsole:
				data = '{}'.format(helpMsg(dh))
				for key in self.dhConsole.get(dh):
					data += '[{}] = {}\n'.format(key,self.dhConsole.get(dh).get(key) )
				log.info(data)
			return True

		elif cmd[1] == 'calls':

			Usage = {
				"calls":{
					"0":"(debug off)",
					"1":"(debug on)",
				}
			}

			if len(cmd) == 2 or len(cmd) == 3 and cmd[2] == '-h':
				log.info('{}'.format(helpAll(msg=msg, Usage=Usage)))
				return True

			else:
				try:
					if int(cmd[2]) < 0 or int(cmd[2]) > 1:
						log.info('{}'.format(helpAll(msg=msg,Usage=Usage)))
						return False
					self.dh.debugCalls = int(cmd[2])

					log.info('{} {}: {}'.format(cmd[0],cmd[1],self.dh.debugCalls))

				except ValueError as e:
					log.failure("Not valid debug code: {}".format(cmd[2]))
					return False
				return True

		elif cmd[1] == 'traffic':
			Usage = {
				"traffic":{
					"0":"(debug off)",
					"1":"(JSON traffic)",
					"2":"(hexdump traffic)",
					"3":"(hexdump + JSON traffic)",
				}
			}

			if len(cmd) == 2 or len(cmd) == 3 and cmd[2] == '-h':
				if len(cmd) <= 3:
					log.info('{}'.format(helpAll(msg=msg, Usage=Usage)))
					return True
			else:
				try:
					if int(cmd[2]) < 0 or int(cmd[2]) > 3:
						log.info('{}'.format(helpAll(msg=msg,Usage=Usage)))
						return False
					self.dh.debug = int(cmd[2])

					log.info('{} {}: {}'.format(cmd[0],cmd[1],self.dh.debug))
				except ValueError as e:
					log.failure("Not valid debug code: {}".format(cmd[2]))
					return False
				return True

		else:
			log.failure('No such command ({})'.format(msg))
			return True

#############################################################################################################
#
# Dahua instance
#
#############################################################################################################

class Dahua_Functions:

	def __del__(self):

		log.success(color('Successful instance termination of {} ({})'.format(self.DeviceType,self.rhost),GREEN))


	def __init__(self, rhost=None, rport=None, proto=None, username=None, password=None, events=False, ssl=False, timeout=5, udp_server=True ):


		self.rhost = rhost
		self.rport = rport
		self.proto = proto
		if username and password:
			self.auth = username + ':' + password
		else:
			self.auth = None 				# username/hash will be used
		self.events = events
		self.ssl = ssl
		self.timeout = timeout
		self.udp_server = udp_server		# If we don't have own udp server running in main app, will be False and we do not send anything
		self.debug = args.debug

		# Internal sharing
		self.ID = 0							# Our Request / Response ID that must be in all requests and initated by us
		self.SessionID = 0					# Session ID will be returned after successful login

		self.paramsTMP = {}					# Used in instance_create()
		self.attachParamsTMP = []			# Used in instance_create()

		self.InstanceServiceDB = {}			# Store of Object, ProcID, SID, etc.. for 'service'
		self.debugCalls = False 			# Some internal debugging
		self.fuzzDB = {}					# Used when fuzzing some calls
		self.fuzzServiceDB = {}				# Used when fuzzing services

		self.multicall_query_args = [] 		# Used with system.multicall method
		self.RemoteServicesCache = {}	 	# Cache of remote services, used to check if certain service exist or not
		self.RemoteMethodsCache = {}		# Cache of used remote methods
		self.RemoteConfigCache = {}			# Cache of remote config
		self.RestoreEventHandler = {}		# Cache of temporary enabled events

		self.event = threading.Event()
		self.socket_event = threading.Event()
		self.lock = threading.Lock()
		self.terminate = False
		self.DeviceType = '(null)'

	#
	# Debug function
	#
	def DEBUG(self,direction, packet):

		if self.debug:
			packet = packet.encode('latin-1')

			# Print send/recv data and current line number
			print(color("[BEGIN {} ({})] <{:-^40}>".format(direction, self.rhost, inspect.currentframe().f_back.f_lineno),LBLUE))
			if (self.debug == 2) or (self.debug == 3):
				print(hexdump(packet))
			if (self.debug == 1) or (self.debug == 3):
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
						print("{}".format(data.decode('latin-1').strip('\n')))
				elif packet: # Unknown packet, do hexdump
						log.failure("DEBUG: Unknow packet")
						print(hexdump(packet))
			print(color("[ END  {} ({})] <{:-^40}>".format(direction, self.rhost, inspect.currentframe().f_back.f_lineno),BLUE))
		return

	#
	# Device DHIP/DVRIP discover function
	#
	def DHDiscover(self,msg):

		cmd = msg.split()

		Usage = {
			"dhip":"[ipAddr]",
			"dvrip":"[ipAddr]"
		}
		if len(cmd) < 2 or len(cmd) > 3 or cmd[1] == '-h':
			log.info('{}'.format(helpAll(msg=msg,Usage=Usage)))
			return True
		args.discover = cmd[1]

		if args.discover == 'dhip':
			if len(cmd) == 2:
				args.rhost = '239.255.255.251' # Multicast
			else:
				args.rhost = Utility().Host(cmd[2])
				if not args.rhost:
					log.failure("Invalid RHOST")
					return False
		elif args.discover == 'dvrip':
			if len(cmd) == 2:
				args.rhost = '255.255.255.255' # Broadcast
			else:
				args.rhost = Utility().Host(cmd[2])
				if not args.rhost:
					log.failure("Invalid RHOST")
					return False

		if args.discover == 'dhip':
			MCAST_GRP = args.rhost
			MCAST_PORT = 37810

			query_args = {
				"method":"DHDiscover.search",
				"params":{
					"mac":"",
					"uni":1
					},
				}

			header =  p64(0x2000000044484950,endian='big') + p64(0x0) + p32(len(json.dumps(query_args))) + p32(0x0) + p32(len(json.dumps(query_args))) + p32(0x0)
			packet = header + json.dumps(query_args).encode('latin-1')

			socket.setdefaulttimeout(3)
			with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
				sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
				self.DEBUG("SEND",packet.decode('latin-1'))
				sock.sendto(packet, (MCAST_GRP, MCAST_PORT))

				while True:
					try:
						data, addr = sock.recvfrom(4096)
					except (Exception, KeyboardInterrupt, SystemExit) as e:
						return True
					log.success("DHDiscover response from: {}:{}".format(addr[0],addr[1]))
					self.DEBUG("RECV",data.decode('latin-1'))
					data = data[32:].decode('latin-1')
					data = json.loads(data.strip('\x00'))

					print(json.dumps(data,indent=4))

		elif args.discover == 'dvrip':
			BCAST_GRP = args.rhost
			BCAST_PORT = 5050

			packet = p32(0xa3010001,endian='big') + (p32(0x0) * 3) + p32(0x02000000,endian='big') + (p32(0x0) * 3)

			socket.setdefaulttimeout(3)
			with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
				sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
				sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
				self.DEBUG("SEND",packet.decode('latin-1'))
				sock.sendto(packet, (BCAST_GRP, BCAST_PORT))

				while True:
					try:
						data, addr = sock.recvfrom(4096)
					except (Exception, KeyboardInterrupt, SystemExit) as e:
						return True
					log.success("DHDiscover response from: {}:{}".format(addr[0],addr[1]))
					self.DEBUG("RECV",data.decode('latin-1'))

					data = data[32:].decode('latin-1')

					BinInfo = {
						"Version": {
							"Version": "{}.{}.{}.{}".format(u16(data[0:2]), u16(data[2:4]), u16(data[4:6]), u16(data[6:8]))
						},
						"Network": {
							"Hostname": data[8:24].strip('\x00'),
							"IPAddress": util.unbinary_ip(data[24:28]),
							"SubnetMask": util.unbinary_ip(data[28:32]),
							"DefaultGateway": util.unbinary_ip(data[32:36]),
							"DnsServers": util.unbinary_ip(data[36:40]),
							},
						"AlarmServer": {
							"Address": util.unbinary_ip(data[40:44]),
							"Port": u16(data[44:46]), 
							"Unknown46-47": u8(data[46:47]),
							"Unknown47-48": u8(data[47:48]),
						},
						"Email": { # SMTP Server
							"Address": util.unbinary_ip(data[48:52]),
							"Port": u16(data[52:54]),
							"Unknown54-55": u8(data[54:55]),
							"Unknown55-56": u8(data[55:56]),
						},
						"Unknown": {
							"Unknown56-50": util.unbinary_ip(data[56:60]),
							"Unknown60-62": u16(data[60:62]),
							"Unknown82-86": util.unbinary_ip(data[82:86]),
							"Unknown86-88": u16(data[86:88]),
						},
						"Web": {
							"Port": u16(data[62:64]),
							},
						"HTTPS": {
							"Port": u16(data[64:66]),
							},
						"DVRIP": {
							"TCPPort": u16(data[66:68]),
							"MaxConnections": u16(data[68:70]),
							"SSLPort": u16(data[70:72]),
							"UDPPort": u16(data[72:74]),
							"Unknown74-75": u8(data[74:75]),
							"Unknown75-76": u8(data[75:76]),
							"MCASTAddress": util.unbinary_ip(data[76:80]),
							"MCASTPort": u16(data[80:82]),
							},

					}

					log.info("Binary:\n{}".format(json.dumps(BinInfo,indent=4)))
					log.info("Ascii:\n{}".format(data[88:].strip('\x00')))

	#
	# Initate connection to device and handle possible calls from cmd line
	#
	def Connect(self):

		try:
			self.remote = remote(self.rhost, self.rport, ssl=self.ssl, timeout=self.timeout)
		except (Exception, KeyboardInterrupt, SystemExit):
			return False

		if args.test:
			self.header = self.protoHeader()
			return True

		if not args.dump:
			console = log.progress(color('Dahua JSON Console',YELLOW))
			console.status(color('Trying',YELLOW))

		if self.proto == 'dvrip' or self.proto == '3des':
			if not self.Dahua_DVRIP_Login():
				if not args.dump:
					if args.save:
						console.success('Save host')
					else:
						console.failure(color("Failed",RED))
					return False
				else:
					return False

		elif self.proto == 'dhip':
			if not self.Dahua_DHIP_Login():
				if not args.dump:
					if args.save:
						console.success('Save host')
					else:
						console.failure(color('Failed',RED))
					return False
				else:
					return False

		query_args = {
		"method": "magicBox.getDeviceType",
			"params": None,
			"session": self.SessionID,
			"id": self.ID
		}
		self.SendCall(query_args, multicall=True)

		# Used for enable/disable certain functions
		#
		# Classes: NVR, IPC, VTO, VTH, DVR
		#
		query_args = {
		"method": "magicBox.getDeviceClass",
			"params": None,
			"session": self.SessionID,
			"id": self.ID
		}
		self.SendCall(query_args, multicall=True)

		query_args = {
		"method": "global.getCurrentTime",
			"params": None,
			"session": self.SessionID,
			"id": self.ID
		}
		data = self.SendCall(query_args, multicall=True, multicallsend=True)

		self.DeviceClass = data.get('magicBox.getDeviceClass').get('params').get('type') if not data.get('magicBox.getDeviceClass').get('error') else False
		self.DeviceType = data.get('magicBox.getDeviceType').get('params').get('type')

		log.info("Remote Model: {}, Class: {}, Time: {}".format(
			self.DeviceType,
			self.DeviceClass,
			data.get('global.getCurrentTime').get('params').get('time'),
			))

		if args.dump:
			return True

		if not self.InstanceService('console',attach=True,start=True):
			console.failure(color("Attach Console failed, using local only",LRED))
			self.ConsoleAttach = False
		else:
			self.ConsoleAttach = True
			console.success(color('Success',GREEN))

		self.eventManager(msg='events 1')

		return True

	#
	# Send command to remote console, if not attached just ignore sending
	#
	def runCmd(self,msg):

		query_args = {
			"SID":self.InstanceService('console',pull='sid'),
			"id":self.ID,
			"method":"console.runCmd",
			"params":{
				"command":msg,
				},
			"object":self.InstanceService('console',pull='object'),
			"session":self.SessionID
			}
		if self.ConsoleAttach or args.force:
			data = self.P2P(json.dumps(query_args))
			if not data:
				# Try catch the 'result'
				data = self.P2P(json.dumps(query_args),recv=True)
				if not data:
					return False
			if not data == None:
				try:
					data = json.loads(data)
				except json.decoder.JSONDecodeError as e:
					log.failure('JSONDecodeError: {}'.format(e))
					print(data)

				if not data.get('result'):
					log.failure("Invalid command: 'help' for help")


	#
	# This function will act as the delay for keepAlive of the connection
	# At same time it will check and process any late incoming packets every second, which will end up in clientNotifyData()
	#
	def sleep_check_socket(self,delay):
		keepAlive = 0
		sleep = 1

		while True:
			if delay <= keepAlive:
				break
			else:
				keepAlive += sleep
				if self.terminate:
					break
				# If received data and not another process locked P2P(), should be callback, break
				if self.remote.can_recv() and not self.lock.locked():
					try:
						data = self.P2P(packet=None,recv=True)
						#
						# Will always return list
						#
						data = fix_json(data)
						for NUM in range(0,len(data)):
							self.checkForKeepAlive(data[NUM])
					except (AttributeError, ValueError, TypeError) as e:
						log.failure('sleep_check_socket(): ({}) {}'.format(e,data))
						pass
				time.sleep(sleep)
				continue
	#
	# Main keepAlive thread
	#
	def P2P_timeout(self,threadName,delay):

		keepAlive = log.progress(color('keepAlive thread',YELLOW))
		keepAlive.success(color('Started',GREEN))

		self.keepAliveTimeOut = 0

		while True:
			self.sleep_check_socket(delay)

			query_args = {
				"method":"global.keepAlive",
				"params":{
					"timeout":delay,
					"active":True
					},
				"id":self.ID,
				"session":self.SessionID}
			if self.terminate:
				return False
			try:
				if not self.remote.connected() or self.keepAliveTimeOut == keepAliveTimeOut:
					log.warning('self termination ({})'.format(self.rhost))
					self.terminate = True
					self.remote.close()
					return False
			except Exception as e:
				log.failure('keepAlive'.format(e))

			data = self.P2P(json.dumps(query_args))
			if self.terminate:
				return False

			if data == None:
				log.failure('keepAlive fail ({})'.format(self.rhost))
				self.keepAliveTimeOut +=1
				self.event.set()
				continue
			#
			# Will always return list
			#
			data = fix_json(data)
			for NUM in range(0,len(data)):
				self.checkForKeepAlive(data[NUM])

	def checkForKeepAlive(self,data):
		try:
			# keepAlive answer
			if data.get('result') and data.get('params').get('timeout'):
				if self.event.is_set():
					log.success("keepAlive back")
					self.keepAliveTimeOut = 0
					self.event.clear()
			else:
				# Not keepAlive answer, send it away to clientNotify
				# check for 'client.' callback 'method' or other stuff
				if data:
					self.clientNotify(json.dumps(data))
		except AttributeError as e:
			if data:
				self.clientNotify(json.dumps(data))
			pass
	#
	# Handle all external communication to and from device
	#
	def P2P(self, packet,recv=False):
		P2P_header = ""
		P2P_data = ""
		P2P_return_data = []
		header_LEN = 0
		LEN_RECVED = 0
		data = ''

		self.lock.acquire()

		if not recv:
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
				if self.lock.locked():
					self.lock.release()
				return None

			self.ID += 1

			#
			# Replicating how Dahua sending data (not working for upload to device)
			#
			# [JSON] + \n + [DATA]
			#
			#
			try:
				if json.loads(packet).get('transfer'):
					packet = json.loads(packet)
					dataOut = b64d(packet.get('transfer'))
					packet.pop('transfer')
					packet = json.dumps(packet) + '\n' + dataOut
			except (JSONDecodeError,AttributeError) as e:
				pass

			self.DEBUG("SEND",header.decode('latin-1') + packet)

			try:
				if not self.remote.connected():
					log.error("Connection closed")
					return False
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
		start = time.time()
		LEN_EXPECT = 0
		WAIT = 20
		TIMEOUT = 0.5

		# Checking in binary header for the amount of data to be received
		while True:
			try:
				data = self.remote.recv(numb=32,timeout=TIMEOUT).decode('latin-1')
#				print('[1] len',len(data))
#				print(data)
				if len(data):
					if self.proto == 'dhip':
						if data[0:8] == p64(0x2000000044484950,endian='big').decode('latin-1'):
							LEN_EXPECT = u32(data[24:28]) + 32
						else:
							print('Not DHIP')
							print(data)
					elif self.proto == 'dvrip' or self.proto == '3des':
						if DahuaProto(data[0:4]):
							tmp = binascii.b2a_hex(data.encode('latin-1')).decode('latin-1')
							proto = [
								'b000',
								'b001',
								]
							# Field for amount of data in DVRIP/3DES differs
							if tmp[0:4] in proto:
								LEN_EXPECT = u32(data[4:8]) + 32
							else:
								LEN_EXPECT = u32(data[16:20]) + 32
						else:
							print('Not DVRIP')
							print(data)

					if LEN_EXPECT:
#						print('LEN_EXPECT',LEN_EXPECT)
						while True:
							data += self.remote.recv(numb=1024,timeout=TIMEOUT).decode('latin-1')
#							print('[3] len',len(data))

							if len(data) >= LEN_EXPECT:
								if self.remote.can_recv():
#									print('more data')
									continue
								break
							# Prevent infinite loop
							if time.time() - start > WAIT:
								break
						break

				# Prevent infinite loop
				if time.time() - start > WAIT:
					log.failure('Timeout in P2P')
					if self.lock.locked():
						self.lock.release()
					return False

			except KeyboardInterrupt as e:
				if self.lock.locked():
					self.lock.release()
				return False
			except EOFError:
				break

		if not len(data):
			if self.lock.locked():
				self.lock.release()
				log.failure("Nothing received from remote!")
				return None

		while len(data):
			# DHIP
			if data[0:8] == p64(0x2000000044484950,endian='big').decode('latin-1'):
				P2P_header = data[0:32]
				LEN_RECVED = u32(data[16:20])
				LEN_EXPECT = u32(data[24:28])
				data = data[32:]
			# DVRIP
			elif DahuaProto(data[0:4]):
				LEN_RECVED = u32(data[4:8])
				LEN_EXPECT = u32(data[16:20])
				P2P_header = data[0:32]

				if P2P_header[24:28].encode('latin-1') == p32(0x0600f900,endian='big'):
					self.SessionID = u32(P2P_header[16:20])
					self.AuthCode = binascii.b2a_hex(P2P_header[28:32].encode('latin-1')).decode('latin-1')
					self.ErrorCode = binascii.b2a_hex(P2P_header[8:12].encode('latin-1')).decode('latin-1')

				if len(data) == 32:
					self.DEBUG("RECV",P2P_header)
					if self.lock.locked():
						self.lock.release()
				data = data[32:]
			else:
				if LEN_RECVED == 0:
					log.failure("P2P: Unknow packet")
					print("PROTO: \033[92m[\033[91m{}\033[92m]\033[0m".format(binascii.b2a_hex(data[0:4].encode('latin-1')).decode('latin-1')))
					print(hexdump(data))
					if self.lock.locked():
						self.lock.release()
					return None
				P2P_data = data[0:LEN_RECVED]
				if LEN_RECVED:
					self.DEBUG("RECV",P2P_header + P2P_data)
					try:
						tmp = json.loads(P2P_data)
						if tmp.get('callback'):
							self.clientNotify(json.dumps(tmp))
							P2P_data = ''
					except (ValueError, AttributeError) as e:
						pass
				else:
					self.DEBUG("RECV",P2P_header)
				if len(P2P_data):
					P2P_return_data.append(P2P_data)
				data = data[LEN_RECVED:]
				if self.lock.locked():
					self.lock.release()
				if LEN_RECVED == LEN_EXPECT and not len(data):
					break

		return ''.join(map(str, P2P_return_data))

	#
	# DHIP Login function
	#
	def Dahua_DHIP_Login(self):

		login = log.progress(color('Login',YELLOW))

		LogIn = pwdManager(rhost=self.rhost, auth=self.auth, login=login)

		self.header = self.protoHeader()

		query_args = {
			"id" : self.ID,
			"method":"global.login",
			"params":{
				},
			"session":self.SessionID
			}
		params = LogIn.DHIP(query_args)
		if not params:
			return False
		query_args.get('params').update(params)

		data = self.SendCall(query_args,errorcodes=True)
		if data == False or data == None:
			login.failure("global.login [random]")
			return False

		if not data.get('error').get('code') == 268632079: # Login Challenge
			login.failure("global.login {}".format(data.get('error')))
			return False

		self.SessionID = data.get('session')

		# TODO: Need this now for possible SaveHost()
		REALM = data.get('params').get('realm')

		query_args = {
			"id":self.ID,
			"method":"global.login",
			"params":{
				},
			"session":self.SessionID,
			}
		data = LogIn.DHIP(data)
		if data == False:
			return False

		query_args.get('params').update(data)

		data = self.SendCall(query_args,errorcodes=True)
		if data == False:
			return False

		if data.get('error') and data.get('error').get('code') == 268632086: # Device not initialised
			login.failure(color('Device not initialised! ({})'.format(data.get('params')),RED))
			return False

		elif not data.get('result'):
			login.failure(color('global.login: {}'.format(data.get('error')),RED))
			return False

		login.success(color('Success',GREEN))

		if args.save:
			LogIn.SaveHost(self.rhost,self.rport,self.proto,self.auth,REALM)
			return False

		if not args.dump:
			keepAlive = data.get('params').get('keepAliveInterval')
			_thread.start_new_thread(self.P2P_timeout,("P2P_timeout", keepAlive,))

		return True

	#
	# 3DES/DVRIP Login function
	#
	def Dahua_DVRIP_Login(self):

		login = log.progress(color('Login',YELLOW))

		LogIn = pwdManager(rhost=self.rhost, auth=self.auth, login=login)

		if self.proto == '3des':

			data = LogIn.DVRIP({
				"proto":self.proto
				})
			if not data:
				return False

			# all characters above 8 will be stripped
			self.header =  p32(0xa0000000,endian='big') + p32(0x0) + data.get('username') + data.get('password') + p64(0x050200010000a1aa,endian='big')

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

			# TODO: Need this now for possible SaveHost()
			REALM = data.split('\r\n')[0].split(':')[1] if data.split('\r\n')[0].split(':')[0] == 'Realm' else None

			data = LogIn.DVRIP({
				"proto":self.proto,
				"realm":data.split('\r\n')[0].split(':')[1] if data.split('\r\n')[0].split(':')[0] == 'Realm' else None,
				"random":data.split('\r\n')[1].split(':')[1] if data.split('\r\n')[1].split(':')[0] == 'Random' else None
				})
			if not data:
				return False

			self.header = p32(0xa0050000,endian='big') + p32(len(data.get('hash'))) + (p8(0x00) * 16) + p64(0x050200080000a1aa,endian='big')

			data = self.P2P(data.get('hash'))
			if data == None:
				return False

		if self.ErrorCode[:4] == '0008':
			login.success(color('Success',GREEN))
		elif self.ErrorCode[:4] == '0100':
			login.failure('Authentication failed: {} tries left {}'.format(int(self.AuthCode[2:4],16), '(BUG: SessionID = {})'.format(self.SessionID) if self.SessionID else ''))
			return False
		elif self.ErrorCode[:4] == '0101':
			login.failure('Username invalid')
			return False
		elif self.ErrorCode[:4] == '0104':
			login.failure('Account locked: {}'.format(data))
			return False
		elif self.ErrorCode[:4] == '0105':
			login.failure('Undefined code: {}'.format(self.ErrorCode[:4]))
			return False
		elif self.ErrorCode[:4] == '0111':
			login.failure('Device not initialised: {}'.format(self.ErrorCode[:4]))
			return False
		elif self.ErrorCode[:4] == '0113':
			login.failure('Not implemented: {}'.format(self.ErrorCode[:4]))
			return False
		elif self.ErrorCode[:4] == '0303':
			login.failure('User already connected')
			return False
		else:
			login.failure(color('Unknown ErrorCode: {}'.format(self.ErrorCode[:4]),RED))
			return False

		if args.save and not self.proto == '3des':
			LogIn.SaveHost(self.rhost,self.rport,self.proto,self.auth,REALM)
			return False

		if not args.dump:
			keepAlive = 30 # Seems to be stable
			_thread.start_new_thread(self.P2P_timeout,("P2P_timeout", keepAlive,))

		self.header = self.protoHeader()

		return True

	def protoHeader(self):

		if self.proto == 'dhip':
			return p64(0x2000000044484950,endian='big') +'_SessionHexID__ID__LEN_'.encode('latin-1') + p32(0x0) +'_LEN_'.encode('latin-1')+ p32(0x0) 
		else:
			# DVRIP
			return p32(0xf6000000,endian='big') + '_LEN__ID_'.encode('latin-1') + p32(0x0) + '_LEN_'.encode('latin-1') + p32(0x0) + '_SessionHexID_'.encode('latin-1') + p32(0x0)


	#############################################################################################################
	#
	# Internal functions, should never be called directly
	#
	#############################################################################################################

	def ConsoleResult(self,msg,callback=False):

		#
		# Not sure how this looks like, catch the callback and just dump it to console
		#
		# NVR additional 'console' w/ console.attachAsyncResult, console.detachAsyncResult
		if msg.get('method') == 'client.notifyConsoleAsyncResult':
			log.info("callback: {}".format(msg.get('method')))
			print(json.dumps(msg,indent=4))
			return True

		paramsinfo = msg.get('params').get('info')

		if not int(paramsinfo.get('Count')):
			log.warning("(null) data received from Console")
			return False

		for paramscount in range(0,int(paramsinfo.get('Count'))):
			print(str(paramsinfo.get('Data')[paramscount]).strip('\n'))
		return True

	#
	# Any late data processed from the 'P2P_timeout()' thread coming from remote device will end up here,
	# sort out with "client.notify....." callback
	#
	def clientNotify(self,data):
		#
		# Some stuff prints sometimes 'garbage', like 'dvrip -l'
		#
		data = ndjson.loads(data,strict=False)

		for NUM in range(0,len(data)):
			data = data[NUM]

			if data.get('method') == 'client.notifyConsoleResult':
				return self.ConsoleResult(msg=data,callback=True)

			elif data.get('method') == 'client.notifyConsoleAsyncResult':
				return self.ConsoleResult(msg=data,callback=True)

			elif data.get('method') == 'client.notifyDeviceInfo':
				return self.deviceDiscovery(msg=data,callback=True)

			elif data.get('method') == 'client.notifyEventStream':

				if self.udp_server:
					data['ipAddr'] = self.rhost

					#
					# Send off to main event handler
					#
					notifyEvent = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
					notifyEvent.sendto(json.dumps(data).encode('latin-1'), ("127.0.0.1", EventInServerPort))
					notifyEvent.close()
			else:
				try:
					if data.get('method'):
						log.failure(color("unhandled callback: {}".format(data.get('method')),RED))
						print(json.dumps(data,indent=4))
					else:
						self.checkForloop(data)

				except AttributeError as e:
					self.checkForloop(data,e)

			return True

	def checkForloop(self,data,error=''):

		if not data.get('loop'):
			log.warning(color('clientNotify(): Got some others data: {} {}'.format(data,error),RED))

			time.sleep(2)

			self.lock.acquire()
			log.info(color('clientNotify(): sending back to recv()',YELLOW))
			data.update({"loop":True})
			header = copy.copy(self.header)
			header = header.replace('_SessionHexID_'.encode('latin-1'),p32(self.SessionID))
			header = header.replace('_LEN_'.encode('latin-1'),p32(len(data)))
			header = header.replace('_ID_'.encode('latin-1'),p32(data.get('id')) if data.get('id') else p32(self.ID))
			self.remote.unrecv(header + json.dumps(data).encode('latin-1'))
			if self.lock.locked():
				self.lock.release()
		else:
			log.success(color('clientNotify(): Identified loop, remove from recv()'.format(data),GREEN))
			pass

	def testLoop(self,data):
		data = json.loads(data)

		self.lock.acquire()
		header = copy.copy(self.header)
		header = header.replace('_SessionHexID_'.encode('latin-1'),p32(self.SessionID))
		header = header.replace('_LEN_'.encode('latin-1'),p32(len(data)))
		header = header.replace('_ID_'.encode('latin-1'),p32(data.get('id')) if data.get('id') else p32(self.ID))
		self.remote.unrecv(header + json.dumps(data).encode('latin-1'))
		if self.lock.locked():
			self.lock.release()

	#############################################################################################################
	#
	# Common functions
	#
	#############################################################################################################


	def SendCall(self, query_args, multicall=False, multicallsend=False, errorcodes=False,debug=False):
		debug = self.debugCalls
		#
		# Single call
		#
		if query_args == None:
			query_args = ''

		#
		# Single call
		#
		if not multicall and not len(self.multicall_query_args):
			if len(query_args) and not query_args.get('params') == None:
				if not len(query_args.get('params')): query_args.update({"params":None})

			try:
				data = self.P2P(json.dumps(query_args))
			except KeyboardInterrupt as e:
				raise KeyboardInterrupt
				return False

			if data == False:
				return False

			if data == None or not len(data):
				if debug:
					log.failure(color("No data back with query: ({})".format(query_args.get('method')),LRED))
				# Lets listen again, keepAlive might got it and sent back to recv()
				data = self.P2P(packet=None,recv=True)
				if not data:
					return False

			#
			# Replicating how Dahua sending data, so we pass on received data with "transfer"
			#
			# packet + split('\n')
			# [JSON][0]
			# [DATA][1]
			#
			#
			try:
				data = json.loads(data)
			except (AttributeError, JSONDecodeError) as e:
				if not data.find('\n'):
					log.failure("[1] SendCall data: ({}) {}".format(e,data))
					pass
				tmp = data.split('\n')
				data = json.loads(tmp[0])
				data.update({"transfer":b64e(tmp[1])})
				pass

			if not data.get('result') and data.get('error'):
				if debug:
					log.failure(color("query: {}".format(query_args),LRED))
					log.failure(color("response: {}: {}".format('(pthread) error' if data.get('error').get('code') == 268632080 else 'error', data.get('error')),LRED))

				if errorcodes:
					return data
				else:
					return False

			return data
		#
		# Multi call
		#
		if not len(self.multicall_query_args):
			self.multicall_query_args = []
			self.multicall_data = []

		#
		# Normally we will return JSON data with key as the 'method' name when 'params' is None
		# Others we will use 'params' name, as the 'method' name can be the same for different calls
		#
		# TODO:
		# For now we need to specify some known calls, should be bit smarter to handle all kind of methods
		# (maybe by only using ID)
		#

		# Just to make 'params' consistent both if it is 'None' or '{}'	
		if len(query_args) and not query_args.get('params') == None:
			if not len(query_args.get('params')): query_args.update({"params":None})

		if len(query_args):
			if query_args.get('params') == None:
				method = query_args.get('method')
			elif query_args.get('method') == 'configManager.getConfig' and query_args.get('params').get('name'):
				method = query_args.get('params').get('name')
			elif query_args.get('method') == 'configManager.setConfig' and query_args.get('params').get('name'):
				method = query_args.get('params').get('name')
			elif query_args.get('method') == 'configManager.getDefault' and query_args.get('params').get('name'):
				method = query_args.get('params').get('name')
			elif query_args.get('method').split('.')[0] == 'netApp':
				method = query_args.get('method')# + query_args.get('params').get('Name')
			#
			# Very beta test
			#
			elif query_args.get('id'):
				method = query_args.get('id')

			else:
				log.failure("(multicall): {}".format(query_args.get('method')))
				return False

			self.multicall_query_args.append(query_args)
			self.multicall_data.append({"id":query_args.get('id'),"method":method})

			self.ID += 1 # Not good idea to have one additional outside of P2P, but is needed (for now)

		if multicall and multicallsend and len(self.multicall_query_args):
			#
			self.multicall_query = {
				"id":self.ID,
				"method":"system.multicall",
				"params": self.multicall_query_args,
				"session":self.SessionID,
				}

			try:
				data = self.P2P(json.dumps(self.multicall_query))
			except KeyboardInterrupt as e:
				self.multicall_query_args = []
				self.multicall_data = []
				raise KeyboardInterrupt
				return False

			if data == None or not data or not len(data):
				if debug:
					log.failure(color("No data back with query: (system.multicall)",LRED))
				# Lets listen again, keepAlive might got it and sent back to recv()
				try:
					data = self.P2P(packet=None,recv=True)
				except KeyboardInterrupt as e:
					self.multicall_query_args = []
					self.multicall_data = []
					raise KeyboardInterrupt
					return False

				if not data:
					return False

			try:
				data = json.loads(data)

			except (AttributeError, JSONDecodeError) as e:
				log.failure("[2] ({}) SendCall data: {}".format(e,data))
				try:
					data += self.P2P(packet=None,recv=True)
				except KeyboardInterrupt as e:
					self.multicall_query_args = []
					self.multicall_data = []
					raise KeyboardInterrupt
					return False

				if not data:
					return False

			if not data.get('result'):
				if debug:
					log.failure(color("query: {}".format(self.multicall_query_args),LRED))
					log.failure(color("response: {}: {}".format('(pthread) error' if data.get('error').get('code') == 268632080 else 'error', data.get('error')),LRED))
				return False

			data = data.get('params')
			tmp = {}

			for key in range(0,len(data)):
				#
				# Looks like to be FIFO, bailout just in case to catch any ID missmatch
				#
				if not self.multicall_data[key].get('id') == data[key].get('id'):
					log.error("Function SendCall() ID missmatch :\nreq: {}\nres: {}".format(self.multicall_data[key], data[key]))
				tmp[self.multicall_data[key].get('method')] = data[key]

			self.multicall_query_args = []
			self.multicall_data = None
			return tmp

	#
	# Checking and caches if a service exist or not
	#
	def CheckForService(self, service):

		query_args = {
			"method":"system.listService",
			"session":self.SessionID,
			"params":None,
			"id":self.ID
			}
		if not len(self.RemoteServicesCache):
			self.RemoteServicesCache = self.SendCall(query_args)
			if self.RemoteServicesCache == False:
				return False
		if service == 'dump':
			return

		if self.RemoteServicesCache.get('result'):
			for count in range(0,len(self.RemoteServicesCache.get('params').get('service'))):
				if self.RemoteServicesCache.get('params').get('service')[count] == service:
					return True

		log.failure("Service [{}] not supported on remote device".format(service))
		return False

	#
	# List and caches service(s)
	#
	def listService(self,msg,fuzz=False):

		msg = msg
		cmd = msg.split()

		Usage = {
			"":"(dump all remote services)",
			"<service>":"(dump methods for <service>)",
			"all":"(dump all remote services methods)",
			"help":"[<service>|all] (\"system\" looks like only have builtin help)",
			"[<service>|<all>]":"[save <filename>] (Save JSON to <filename>)",
		}
		if not len(cmd) == 1:
			if cmd[1] == '-h':
				log.info('{}'.format(helpAll(msg=msg,Usage=Usage)))
				return True

		if len(cmd) == 3 and cmd[1] == 'help':
			self.helpService(cmd[2])
			return

		if not self.RemoteServicesCache:
			self.CheckForService('dump')
			if not self.RemoteServicesCache:
				log.failure('EZIP perhaps?')
				return False

		if self.RemoteServicesCache.get('result'):
			if not args.dump:
				service = log.progress('Services')
				service.status("Start")
			tmp = {}
			cache = {}

			for count in range(0,len(self.RemoteServicesCache.get('params').get('service'))):
				if len(cmd) == 1:
					print(self.RemoteServicesCache.get('params').get('service')[count])
				elif len(cmd) == 2 or len(cmd) == 4:

					query_tmp = {
						"method":"",
						"session":self.SessionID,
						"params":None,
						"id":self.ID
						}
					query_tmp.update({'method' : cmd[1] + '.listMethod' if not cmd[1] == 'all' else self.RemoteServicesCache.get('params').get('service')[count] + '.listMethod'})

					if not self.RemoteMethodsCache.get(cmd[1] if not cmd[1] == 'all' else self.RemoteServicesCache.get('params').get('service')[count]):
						if query_tmp.get('method') == 'system.listMethod': # not working with multicall
							data = self.SendCall(query_tmp)
							tmp.update({query_tmp.get('method').split('.')[0]: data})

							data.pop('result')
							data.pop('id')
							data.pop('session') if data.get('session') else log.failure("SessionID BUG ({})".format(query_tmp.get('method').split('.')[0])) # SessionID bug: "method": "snapManager.listMethod"
							self.RemoteMethodsCache.update({query_tmp.get('method').split('.')[0]: data})

							if not cmd[1] == 'all':
								break
							continue
						else:
							self.SendCall(query_tmp,multicall=True)
					else:
						tmp.update({
							cmd[1] if not cmd[1] == 'all' else self.RemoteServicesCache.get('params').get('service')[count]:
							self.RemoteMethodsCache.get(cmd[1] if not cmd[1] == 'all' else self.RemoteServicesCache.get('params').get('service')[count])
							})


					if not args.dump:
						service.status('{} of {}'.format(count+1, len(self.RemoteServicesCache.get('params').get('service')) ))

					if not cmd[1] == 'all':
						break

			data = self.SendCall(None,multicall=True,multicallsend=True)
			if not data:
				return False

			if data == None:
				cache = tmp

			elif not data == None:
				for methodName in copy.deepcopy(data):
					service.status(methodName)

					if not data.get(methodName).get('result'):
						log.failure("Failure to fetch: {}".format(methodName.split('.')[0]))
						continue
					data.get(methodName).pop('result')
					data.get(methodName).pop('id')
					data.get(methodName).pop('session') if data.get(methodName).get('session') else log.failure("SessionID BUG ({})".format(methodName.split('.')[0])) # SessionID bug: "method": "snapManager.listMethod"

					cache.update({methodName.split('.')[0]: data.get(methodName)})
					self.RemoteMethodsCache.update(cache)
				if len(tmp):
					cache.update(tmp)


			if not args.dump:
				service.success('Done')
			if fuzz:
				return self.RemoteMethodsCache
			if len(cmd) == 4 and cmd[2] == 'save':
				if len(cache):
					return self.saveToFile(FileName=cmd[3],data=cache)
				log.failure('Empty')
			if not len(cmd) == 1:
				if len(cache):
					print(json.dumps(cache,indent=4))
				else:
					log.failure('Empty')

			return True
		else:
			log.failure("Failure: {}".format(self.RemoteServicesCache))
			return False
	#
	# Used by 'listService()' and 'config_members()' to save result to file
	#
	def saveToFile(self,FileName,data):

		if not args.force:
			if path.exists(FileName):
				log.failure("File {} exist (force with -f at startup)".format(FileName))
				return False
		try:
			with open(FileName,'w') as File:
				File.write(json.dumps(data))
			log.success("Saved to: {}".format(FileName))
		except IOError as e:
			log.failure("Save {} fail: {}".format(FileName,e))
			return False
		return True


	#
	# In principal useless function, as the only API help seems to cover 'system' only
	#
	# multicall seems not working with this request... (bummer, would saved lots of time when requesting 'all')
	#
	def helpService(self,msg):
		msg = msg
		cmd = msg.split()

		Services = self.listService(msg='service ' + cmd[0], fuzz=True)

		for key in Services.keys():
			for method in Services.get(key).get('params').get('method'):

				query_args = {
					"method":"system.methodHelp",
					"session":self.SessionID,
					"params":{
						"methodName":method,
					},
					"id":self.ID
					}
				data = self.SendCall(query_args)
				query_args = {
					"method":"system.methodSignature",
					"session":self.SessionID,
					"params":{
						"methodName":method,
					},
					"id":self.ID
					}
				data2 = self.SendCall(query_args)

				if not data and not data2:
					continue

				log.info("Method: {:30}Params: {:20}Description: {}".format(
					method,
					data2.get('params').get('signature','(null)'),
					data.get('params').get('description','(null)')
					))


	#
	# Main function to create remote instance and attach (if needed)
	# Storing all details in 'self.InstanceServiceDB', simplifies to create/check/pull/close remote instance
	#
	def InstanceService(self,methodName='',attach=False,params=None,attachParams=None,
		detachParams=None,stop=False,start=False,pull=None,clean=False,listAll=False,fuzz=False,
		AttachOnly=False,multicall=False,multicallsend=False):

		debug = self.debugCalls

		if clean:
			for service in copy.deepcopy(self.InstanceServiceDB):
				if not service == 'console':
					log.warning(color('BUG: InstanceService "{}" should have already been stopped (stop now)'.format(service),LRED))
				if debug:
					log.info('Send stop to: {}'.format(service))
				self.InstanceService(service,stop=True)

			return True

		elif listAll:
			for service in self.InstanceServiceDB:
				data = '{}'.format(helpMsg(service))
				for key in self.InstanceServiceDB.get(service):
					data += '[{}] = {}\n'.format(key,self.InstanceServiceDB.get(service).get(key) )
				log.info(data)
			return True

		elif pull:
			if not methodName in self.InstanceServiceDB:
				if debug:
					log.failure('[pull] methodName: {} do not exist'.format(methodName))
				return False
			if debug:
				log.success('[pull] methodName: {} do exist'.format(methodName))
			return self.InstanceServiceDB.get(methodName).get(pull)

		elif start:
			if not self.CheckForService(methodName):
				if debug:
					log.failure('[service] methodName: {} do not exist'.format(methodName))
				return False
			if methodName in self.InstanceServiceDB:
				if debug:
					log.failure('[create] methodName: {} do exist'.format(methodName))
				return False

			OBJECT, ProcID, SID, Params, AttachPARAMS = self.instance_create(
				method=methodName,
				attach=True if attachParams else attach,
				params=params,
				attachParams=attachParams,
				fuzz=fuzz,
				AttachOnly=AttachOnly,
				multicall=multicall,
				multicallsend=multicallsend,
				)

			if multicall and not multicallsend:
				return

			# More for when fuzzing, we want the Response and not only True/False
			if fuzz and SID or fuzz and OBJECT:
				self.fuzzDB.update({
					methodName:{
						"methodName":methodName,
						"attach":True if attachParams else attach,
						"params":Params,
						"attachParams":AttachPARAMS,
						"object":OBJECT,	# False if failure
						"proc":ProcID,		# methodName
						"sid":SID 			# Response data w/ error code
						}
					})

			if not OBJECT:
				if debug:
					log.failure('[create] Object: {} do not exist'.format(methodName))
				return False

			self.InstanceServiceDB.update({
				methodName:{
					"methodName":methodName,
					"attach":True if attachParams else attach,
					"params":Params,
					"attachParams":AttachPARAMS,
					"object":OBJECT,
					"proc":ProcID,
					"sid":SID
					}
				})

			if debug:
				log.success('[update] {}'.format(methodName))
				self.InstanceService(listAll=True)
			return True


		elif stop:
			if not methodName in self.InstanceServiceDB:
				if debug:
					log.failure('[destroy] methodName: {} do not exist'.format(methodName))
				return False

			result, method, data = self.instance_destroy(
				method=methodName,
				ProcID=self.InstanceServiceDB.get(methodName).get('proc'),
				OBJECT=self.InstanceServiceDB.get(methodName).get('object'),
				detach=self.InstanceServiceDB.get(methodName).get('attach'),
				detachParams=self.InstanceServiceDB.get(methodName).get('attachParams')
				)
			if methodName in self.InstanceServiceDB:
				self.InstanceServiceDB.pop(methodName)
				if debug:
					log.success('[destroy] pop: {}'.format(methodName))
					self.InstanceService(listAll=True)

			if not result:
				if debug:
					log.failure('[destroy,instance_destroy] {} {} {}'.format(result, method, data ))
				return False

		return True

	#
	# Should never be called directly
	#
	def instance_create(self,method,attach=True,params=None,attachParams=None,fuzz=False,AttachOnly=False,multicall=False,multicallsend=False):

			if not AttachOnly:
				query_args = {
					"id":self.ID,
					"method":"{}.factory.instance".format(method),
					"params": params,
					"session":self.SessionID
					}

				if attachParams:
					self.attachParamsTMP.append(attachParams)
				if params:
					self.paramsTMP.update({query_args.get('id'):params})

				data = self.SendCall(query_args,errorcodes=fuzz,multicall=multicall,multicallsend=multicallsend,debug=False)

				if multicall and not multicallsend:
					return None,None,None,None,None

				if data == False:
					return False,"{}.factory.instance".format(method), data, params, None

				if multicall and multicallsend:
					for answer in data:
						if data.get(answer).get('result'):
							break
					data = data.get(answer)
					Params = self.paramsTMP.get(data.get('id'),'error to get "params"')

				if data == None or not data.get('result'):
					return False,"{}.factory.instance".format(method), data, params, None

				OBJECT = data.get('result')
				ProcID = OBJECT

				if not attach:
					self.paramsTMP = {}
					self.attachParamsTMP = []
					return OBJECT, ProcID, None, params if not multicall else Params, None

			if AttachOnly:
				OBJECT = AttachOnly
				ProcID = AttachOnly


			if multicall and multicallsend:

				attachID = {}

				for paramsTmp in self.attachParamsTMP:
					query_args = {
						"id":self.ID,
		#				"method":"{}.attachAsyncResult".format(method),	# .params.cmd needed
						"method":"{}.attach".format(method),
						"params": {
							"proc":ProcID,
		#					"cmd":"????",	# .attachAsyncResult
							},
						"object":OBJECT,
						"session":self.SessionID
						}

					query_args.get('params').update(paramsTmp)
					attachID.update({query_args.get('id'):paramsTmp})

					data = self.SendCall(query_args,errorcodes=fuzz,multicall=True,multicallsend=False,debug=False)


				query_args = {
					"id":self.ID,
	#				"method":"{}.attachAsyncResult".format(method),	# .params.cmd needed
					"method":"{}.attach".format(method),
					"params": {
						"proc":ProcID,
	#					"cmd":"????",	# .attachAsyncResult
						},
					"object":OBJECT,
					"session":self.SessionID
					}

				data = self.SendCall(query_args,errorcodes=fuzz,multicall=True,multicallsend=True,debug=False)

				if data == False:
						self.instance_destroy(method=method,ProcID=ProcID,OBJECT=OBJECT,detach=False)
						return False,"{}.attach".format(method), data, Params, attachParams

				for answer in data:
					if data.get(answer).get('result'):
						break
				data = data.get(answer)
				attachParams = attachID.get(data.get('id'),'error to get "attachParams"')

			else:
				query_args = {
					"id":self.ID,
	#				"method":"{}.attachAsyncResult".format(method),	# .params.cmd needed
					"method":"{}.attach".format(method),
					"params": {
						"proc":ProcID,
	#					"cmd":"????",	# .attachAsyncResult
						},
					"object":OBJECT,
					"session":self.SessionID
					}

				if attachParams:
					query_args.get('params').update(attachParams)
				data = self.SendCall(query_args,errorcodes=fuzz,multicall=multicall,multicallsend=multicallsend,debug=False)

			if data == False and not AttachOnly:
					self.instance_destroy(method=method,ProcID=ProcID,OBJECT=OBJECT,detach=False)
					return False,"{}.attach".format(method), data, params if not multicall else Params, attachParams

			if not data.get('result'):
				if OBJECT and not AttachOnly:
					self.instance_destroy(method=method,ProcID=ProcID,OBJECT=OBJECT,detach=False)
				return False,"{}.attach".format(method), data, params if not multicall else Params, attachParams

			SID = data.get('params').get('SID')

			self.paramsTMP = {}
			self.attachParamsTMP = []
			return OBJECT, ProcID, SID, params if not multicall else Params, attachParams

	#
	# Should never be called directly
	#
	def instance_destroy(self, method, ProcID, OBJECT, detach=True, detachParams=None):

			if detach:
				query_args = {
					"id":self.ID,
#					"method":"{}.detachAsyncResult".format(method),	# .params.cmd needed
					"method":"{}.detach".format(method),
					"params":{
						"proc":ProcID,
#						"cmd":"????",	# .detachAsyncResult
						},
					"object":OBJECT,
					"session":self.SessionID
					}
				if detach and detachParams:
					query_args.get('params').update(detachParams)

				data = self.SendCall(query_args)
				if data == False or not data:
					return False, "{}.detach".format(method), data

				if not data.get('result'):
					return False, "{}.detach".format(method), data

			query_args = {
				"id":self.ID,
				"method":"{}.destroy".format(method),
				"params":None, 
				"object":OBJECT,
				"session":self.SessionID
				}

			data = self.SendCall(query_args)
			if data == False:
				return False, "{}.destroy".format(method), data

			if not data.get('result'):
				return False, "{}.destroy".format(method), data

			return True, "{}.destroy".format(method), data

	#
	# 'Hard reboot' of remote device
	#
	def reboot(self,msg=None,delay=0):

		query_args = {
			"method":"magicBox.reboot",
			"params": {
				"delay":delay
				},
			"session":self.SessionID,
			"id":self.ID
			}

		data = self.SendCall(query_args)
		self.socket_event.set()
		log.success("Trying to force reboot")

	#
	# Clean up before we quit, if needed (and can do so)
	#
	def cleanup(self):
		if self.InstanceService('eventManager',pull='object'):
			self.eventManager(msg="events 0")
		if self.InstanceService('deviceDiscovery',pull='object'):
			self.deviceDiscovery(msg='rdiscover stop')

	def logout(self):

		if not self.remote.connected():
			log.failure('Not connected, cannot exit clean')
			return False
		#
		# Will exit the instance by check daemon thread
		#
		if self.terminate and self.remote.connected():
			self.remote.close()
			return False

		#
		# keepAlive failed or terminate
		#
		# Clean up before we quit, if needed (and can do so)
		#
		if not self.event.is_set():
			self.cleanup()

		#
		# Stop console (and possible others)
		#
		self.InstanceService(clean=True)

		query_args = {
			"method":"global.logout",
			"params":None,
			"session":self.SessionID,
			"id":self.ID
			}

		data = self.SendCall(query_args)
		if not data:
			log.failure("global.logout: {}".format(data))
			self.remote.close()
			return False
		if data.get('result'):
			log.success("Logout")
			self.remote.close()
		return True

	def config_members(self,msg):

		cmd = msg.split()

		Usage = {
			"members":"(show config members)",
			"all":"(dump all remote config)",
			"<member>":"(dump config for <member>)",
			"[<member>|<all>]":"[save <filename>] (Save JSON to <filename>)",
			"":"(Use 'ceconfig' in Console to set/get)",
		}
		if len(cmd) == 1 or cmd[1] == '-h':
			log.info('{}'.format(helpAll(msg=msg,Usage=Usage)))
			return False

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
		data = self.SendCall(query_args,errorcodes=True)
		if not data or not data.get('result'):
			log.failure('Error: {}'.format(data.get('error') if data else False))
			return False

		data.pop('id')
		data.pop('session')
		data.pop('result')

		if len(cmd) == 4 and cmd[2] == 'save':
			return self.saveToFile(FileName=cmd[3],data=data)

		print(json.dumps(data,indent=4))

		return

	#
	# VTO specific functions (not complete)
	#
	def open_door(self, msg):

		cmd = msg.split()

		Usage = {
			"<n>":{
				"open":"(open door <n>)",
				"close":"(close door <n>)",
				"status":"(status door <n>)",
				"finger":"(<Undefined>)",
				"password":"(<Undefined>)",
				"lift":"(<Undefined> Not working)",
				"face":"(<Undefined> Not working)",
			}
		}
		if len(cmd) != 3 or cmd[1] == '-h':
			log.info('{}'.format(helpAll(msg=msg,Usage=Usage)))
			return True

		methodName = 'accessControl'

		try:
			door = int(cmd[1])
		except ValueError as ex:
			log.failure("Invalid door number {}".format(cmd[1]))
			self.InstanceService(methodName,stop=True)
			return False

		self.InstanceService(methodName,params={"channel": door},start=True)
		OBJECT = self.InstanceService(methodName,pull='object')
		if not OBJECT:
			return False

		if cmd[2] == 'open':
			query_args = {
				"method": "accessControl.openDoor",
				"params": {
						"DoorIndex": door,
						"ShortNumber": "9901#0",
						"Type": "Remote",
						"OpenDoorType":"Remote",
#						"OpenDoorType":"Dahua",
#						"OpenDoorType":"Local",
						"UserID":"",
						},
				"object": OBJECT,
				"session":self.SessionID,
				"id":self.ID
				}

			data = self.SendCall(query_args)
			print(query_args)
			print(data)
			if data == False:
				return

			log.info("door: {} {}".format(door, "Success" if data.get('result') else "Failure"))

		elif cmd[2] == 'close':
			query_args = {
				"method": "accessControl.closeDoor", # {"id":21,"result":true,"session":2147483452}
				"params": {
#						"Type": "Remote",
#						"UserID":"",
						},
				"object": OBJECT,
				"session":self.SessionID,
				"id":self.ID
				}

#			print(query_args)
			data = self.SendCall(query_args)
			print(query_args)
			print(data)

		elif cmd[2] == 'status':	# Seems always to return "Status Close"
			query_args = {
				"method": "accessControl.getDoorStatus", # {"id":8,"params":{"Info":{"status":"Close"}},"result":true,"session":2147483499}
				"params": {
						"DoorState":door,
#						"ShortNumber": "9901#0",
#						"Type": "Remote",
						},
				"object": OBJECT,
				"session":self.SessionID,
				"id":self.ID
				}
			data = self.SendCall(query_args)
			print(query_args)
			print(data)

		elif cmd[2] == 'finger':
			query_args = {
				"method": "accessControl.captureFingerprint", # working
				"params": {
						},
				"object": OBJECT,
				"session":self.SessionID,
				"id":self.ID
				}
			data = self.SendCall(query_args)
			print(query_args)
			print(data)

		elif cmd[2] == 'lift':
			query_args = {
				"method": "accessControl.callLift", # Not working
				"params": {
					"Src":1,
					"DestFloor":3,
					"CallLiftCmd":"",
					"CallLiftAction":"",
						},
				"object": OBJECT,
				"session":self.SessionID,
				"id":self.ID
				}
			data = self.SendCall(query_args)
			print(query_args)
			print(data)

		elif cmd[2] == 'password':
			query_args = {
				"method": "accessControl.modifyPassword", # working
				"params": {
					"type":"",
					"user":"",
					"oldPassword":"",
					"newPassword":"",
						},
				"object": OBJECT,
				"session":self.SessionID,
				"id":self.ID
				}
			data = self.SendCall(query_args)
			print(query_args)
			print(data)

		elif cmd[2] == 'face':
			query_args = {
				"method": "accessControl.openDoorFace", # Not working
				"params": {
					"Status":"",
					"MatchInfo":"",
					"ImageInfo":"",
						},
				"object": OBJECT,
				"session":self.SessionID,
				"id":self.ID
				}
			data = self.SendCall(query_args)
			print(query_args)
			print(data)

			self.InstanceService(methodName,stop=True)

		return

	def telnetd_SSHD(self,msg):

		cmd = msg.split()

		if cmd[0] == 'telnet':
			SERVICE = 'Telnet'
		elif cmd[0] == 'sshd':
			SERVICE = 'SSHD'

		Usage = {
			"1":"(enable)",
			"0":"(disable)",
		}
		if len(cmd) == 1 or cmd[1] == '-h':
			log.info('{}'.format(helpAll(msg=msg,Usage=Usage)))

			return True

		if cmd[1] == '1':
			enable = True
		elif cmd[1] == '0':
			enable = False
		else:
			log.info('{}'.format(helpAll(msg=msg,Usage=Usage)))
			return False

		query_args = {
			"method":"configManager.getConfig",
			"params": {
				"name":SERVICE,
				},
			"session":self.SessionID,
			"id":self.ID
			}

		data = self.SendCall(query_args)
		if data == False:
			return

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

		data = self.SendCall(data,errorcodes=True)

		if data.get('result'):
			log.success("{}: {}".format(cmd[0],"Enabled" if enable else "Disabled"))
		else:
			log.failure("Failure: {}".format(data))
			return


	def methodBanned(self,msg):

		banned = [
			"system.listService",
			"magicBox.exit",
			"magicBox.restart",
			"magicBox.shutdown",
			"magicBox.reboot",
			"magicBox.resetSystem",
			"magicBox.config"
			"global.login",
			"global.logout",
			"global.keepAlive",
			"global.setCurrentTime",
			"DockUser.addUser",
			"DockUser.modifyPassword",
			"configManager.detach",		# 
			"configManager.exportPackConfig",	# Exporting config in encrypted TGZ
			"configManager.secGetDefault",
			"userManager.deleteGroup",
			"userManager.setDefault",			# will erase all users
			"PhotoStation.savePhotoDesign",
			"configManager.getMemberNames",
			"PerformanceMonitoring.factory.instance",	# generates client.notifyPerformanceInfo() callback
			"PerformanceMonitoring.attach"				# generates client.notifyPerformanceInfo() callback
			]

		try:
			banned.index(msg)
			data = helpMsg('Banned Match')
			data += '{}\n'.format(msg)
			log.info(data)
#			print('Banned Match: {}'.format(msg))
			return True
		except ValueError as e:
			return False
	#
	# Under development
	#
	def fuzzService(self,msg):

		msg = msg
		cmd = msg.split()

		Usage = {
			"check":{
				"<service>":"(method for <service>)",
				"all":"(all remote services methods)",
				},
			"factory":"(fuzz factory)"
		}
		if not len(cmd) >= 2 or cmd[1] == '-h':
			log.info('{}'.format(helpAll(msg=msg,Usage=Usage)))

			return True

		Result = {}

		Code = [
			268894211, # Request invalid param!
			268959743, # Unknown error! error code was not set in service!
			268632080, # pthread error
			285278247, # ? - with magicBox.resetSystem
			268894208, # Request parse error!
			268894212, # Server internal error!
			268894209, # get component pointer failed or invalid request! (.object needed!)
			]


		#
		# TODO: Can be more than one in one call
		#
		Params = [
				"",
				"channel",		# 0 should always be availible
				"pointer",
				"name",
				"codes",
				"service",
				"group",
				"stream",
				"uuid",
				"UUID",
				"object",
				"interval",	# PerformanceMonitoring.attach
				"composite",
				"path",
				"DeviceID",
				"points",
				"Channel",
				]

		attachOptions = [
				{"type":"FormatPatition"},
				"Network",							# configMember
				["All"],	# eventManager
				0,	# for channel.. etc
				1,
				"System_CONFIG_NETCAMERA_INFO_0",	# uuid
				"System_CONFIG_NETCAMERA_INFO_",	# uuid
				["System_CONFIG_NETCAMERA_INFO_0"],	# uuid
				["System_CONFIG_NETCAMERA_INFO_"],	# uuid
				"/mnt/sd",	
				"/dev/mmc0",
				"/",
				]


		try: # [Main TRY]

			if len(cmd) == 3 and cmd[1] == 'check':

				check = log.progress('Check')
				check.status('Start')

				Services = self.listService(msg='service ' + cmd[2], fuzz=True)

				for key in Services.keys():
					check.status(key)

					methodName = Services.get(key).get('params').get('method')
					self.fuzzServiceDB.update({key: {
						}})

					try:
						methodName.index(key + '.factory.instance')
						self.fuzzServiceDB.get(key).update({"factory":True})

						methodName.index(key + '.attach')
						self.fuzzServiceDB.get(key).update({"attach":True})

					except ValueError as e:

						error = str(e).split("'")[1]
						try:
							if error == key + '.factory.instance':
								self.fuzzServiceDB.get(key).update({"factory":False})
							elif error == key + '.attach':
								self.fuzzServiceDB.get(key).update({"attach":False})

							methodName.index(key + '.attach')
							self.fuzzServiceDB.get(key).update({"attach":True})

						except ValueError as e:
							self.fuzzServiceDB.get(key).update({"attach":False})
							pass

				self.Factory = []
				self.Attach = []
				self.AttachOnly = []

				for key in Services.keys():
					if not self.fuzzServiceDB.get(key).get('factory') and not self.fuzzServiceDB.get(key).get('attach'):
						if self.fuzzServiceDB.get(key):
							self.fuzzServiceDB.pop(key)
						continue
					elif self.methodBanned(key + '.factory.instance'):
						if self.fuzzServiceDB.get(key):
							self.fuzzServiceDB.pop(key)
						continue
					elif self.methodBanned(key + '.attach'):
						if self.fuzzServiceDB.get(key):
							self.fuzzServiceDB.pop(key)
						continue

					if self.fuzzServiceDB.get(key).get('factory'):
						self.Factory.append(key)
					if self.fuzzServiceDB.get(key).get('factory') and self.fuzzServiceDB.get(key).get('attach'):
						self.Attach.append(key)
					if not self.fuzzServiceDB.get(key).get('factory') and self.fuzzServiceDB.get(key).get('attach'):
						self.AttachOnly.append(key)

				check.success('Factory: {}, Attach: {}, AttachOnly: {}\n'.format(len(self.Factory),len(self.Attach),len(self.AttachOnly)))

				data = '{}'.format(helpMsg('Summary'))
				data += '{}{}\n'.format(helpMsg('Factory'),', '.join(self.Factory))
				data += '{}{}\n'.format(helpMsg('Attach'),', '.join(self.Attach))
				data += '{}{}\n'.format(helpMsg('AttachOnly'),', '.join(self.AttachOnly))
				log.success(data)
				return

			elif len(cmd) >= 2 and cmd[1] == 'factory':

				try:
					if not len(self.Factory):
						log.failure('Factory is Empty')
						return False
				except AttributeError as e:
						log.failure('Firstly run {} check'.format(cmd[0]))
						return False

				Factory = []
				if len(cmd) == 2:
					Factory = self.Factory
				elif len(cmd) == 3:
					if cmd[2] in self.Factory:
						Factory.append(cmd[2])
					else:
						log.failure('"{}" do not exist in factory'.format(cmd[2]))
						return False


				for methodName in Factory:
					fuzz = log.progress(methodName)

					if methodName in self.Attach:

						OBJECT = self.InstanceService(methodName,pull='object')
						if not OBJECT:
							fuzz.status(color('Working...',YELLOW))
							self.InstanceService(methodName,attach=True,start=True,fuzz=True)
							OBJECT = self.InstanceService(methodName,pull='object')

						if OBJECT:
							fuzz.success( color(str(self.InstanceService(methodName,pull='object')),GREEN ))
							Result.update({methodName:{"availible":True,
								"params":self.InstanceService(methodName,pull='params'),
								"attachParams":self.InstanceService(methodName,pull='attachParams')
								}})

						if not OBJECT:
							for key in Params:
								for options in attachOptions:
									params = {key:options}
									self.InstanceService(methodName,attach=True,params=params,attachParams=params,start=True,fuzz=True,multicall=True,multicallsend=False)

							self.InstanceService(methodName,attach=True,attachParams=params,start=True,fuzz=True,multicall=True,multicallsend=True)
							OBJECT = self.InstanceService(methodName,pull='object')

							if OBJECT:
								fuzz.success(color(str(self.InstanceService(methodName,pull='object')),GREEN))
								Result.update({methodName:{"availible":True,
									"params":self.InstanceService(methodName,pull='params'),
									"attachParams":self.InstanceService(methodName,pull='attachParams')
									}})
								continue

							if not OBJECT:
								error = self.fuzzDB.get(methodName).get('sid').get('error')
								fuzz.failure(color(json.dumps(error),RED))
								Result.update({methodName:{"availible":False,"code":error.get('code'),"message":error.get('message')}})

					else:
						OBJECT = self.InstanceService(methodName,pull='object')
						if not OBJECT:
							fuzz.status(color('Working...',YELLOW))
							self.InstanceService(methodName,attach=False,start=True,fuzz=True)
							OBJECT = self.InstanceService(methodName,pull='object')

						if OBJECT:
							fuzz.success(color(str(self.InstanceService(methodName,pull='object')),GREEN))
							Result.update({methodName:{"availible":True,
								"params":self.InstanceService(methodName,pull='params'),
								"attachParams":self.InstanceService(methodName,pull='attachParams')
								}})

						if not OBJECT:
							for key in Params:
								for options in attachOptions:
									params = {key:options}
									self.InstanceService(methodName,attach=False,params=params,start=True,fuzz=True,multicall=True,multicallsend=False)

							self.InstanceService(methodName,attach=False,start=True,fuzz=True,multicall=True,multicallsend=True)

							OBJECT = self.InstanceService(methodName,pull='object')
							if OBJECT:
								fuzz.success(color(str(self.InstanceService(methodName,pull='object')),GREEN))
								Result.update({methodName:{"availible":True,
									"params":self.InstanceService(methodName,pull='params'),
									"attachParams":self.InstanceService(methodName,pull='attachParams')
									}})
								continue

							if not OBJECT:
								error = self.fuzzDB.get(methodName).get('sid').get('error')
								fuzz.failure(color(json.dumps(error),RED))
								Result.update({methodName:{"availible":False,"code":error.get('code'),"message":error.get('message')}})

				self.InstanceService(methodName="",listAll=True)
#				print(json.dumps(Result,indent=4))
#				print(json.dumps(self.fuzzDB,indent=4))
#				self.fuzzServiceDB = {} # Reset
				return

			else:
				log.failure('No such command "{}"'.format(msg))

		except KeyboardInterrupt as e: # [Main TRY]
			return False

		return

	def devStorage(self):

		query_args = {
			"id":self.ID,
			"method":"storage.getDeviceAllInfo",
			"params":None, 
			"session":self.SessionID
			}

		data = self.SendCall(query_args)
		if data == False:
			log.failure("\033[92m[\033[91mStorage: Device not found\033[92m]\033[0m")
			return

		if data.get('result'):
			Device = data.get('params').get('info')[0].get('Name')

			methodName = 'devStorage'

			self.InstanceService(methodName,params={"name":Device},start=True)
			OBJECT = self.InstanceService(methodName,pull='object')
			if not OBJECT:
				return False

			query_args = {
				"id":self.ID,
				"method":"devStorage.getDeviceInfo",
				"params": None,
				"object":OBJECT,
				"session":self.SessionID,
				"id":self.ID
				}

			data = self.SendCall(query_args)

			if not data == False:
				if data.get('result'):
					data = data.get('params').get('device')#[storage]
					log.success("\033[92m[\033[91mStorage: \033[94m{}\033[91m\033[92m]\033[0m\n".format(data.get('Name',"(null)")))
					log.info("Capacity: {}, Media: {}, Bus: {}, State: {}".format(
						size(data.get('Capacity',"(null)")),
						data.get('Media',"(null)"),
						data.get('BUS',"(null)"),
						data.get('State',"(null)"),
						))
					log.info("Model: {}, SerialNo: {}, Firmware: {}".format(
						data.get('Module',"(null)") if self.DeviceClass == "NVR" else data.get('Model',"(null)") ,
						data.get('SerialNo',"(null)")if self.DeviceClass == "NVR" else data.get('Sn',"(null)"),
						data.get('Firmware',"(null)"),
						))
					for part in range(0,len(data.get('Partitions'))):
						tmp = data.get('Partitions')[part]
						log.info("{}, FileSystem: {}, Size: {}, Free: {}".format(
							tmp.get('Name',"(null)"),
							tmp.get('FileSystem',"(null)"),
							size(tmp.get('Total',0),si=True),
							size(tmp.get('Remain',0),si=True),
							))

			self.InstanceService(methodName,stop=True)

	def getEncryptInfo(self):

		query_args = {
			"method":"Security.getEncryptInfo",
			"session":self.SessionID,
			"params": None,
			"id":self.ID
			}

		data = self.SendCall(query_args)

		if data == False:
			log.failure("\033[92m[\033[91mEncrypt Info: Fail\033[92m]\033[0m")
			return

		if data.get('result'):
			pub = data.get('params').get('pub').split(",")
			log.success("\033[92m[\033[91mEncrypt Info\033[92m]\033[0m\nAsymmetric: {}, Cipher: {}, Padding: {}, RSA Exp.: {}\nRSA Modulus:\n{}".format(
				data.get('params').get('asymmetric'),
				'; '.join(data.get('params').get('cipher',["(null)"])),
				'; '.join(data.get('params').get('AESPadding',["(null)"])),
				pub[1].split(":")[1],
				pub[0].split(":")[1],
				))
			pubkey = RSA.construct(( int(pub[0].split(":")[1],16),int(pub[1].split(":")[1],16) ))
			print(pubkey.exportKey().decode('ascii'))

	def GetRemoteInfo(self,msg):

		cmd = msg.split()

		if cmd[0] == 'device':

			query_args = {
				"method":"magicBox.getSoftwareVersion",
				"session":self.SessionID,
				"params": None,
				"id":self.ID
				}
			self.SendCall(query_args,multicall=True)

			query_args = {
				"method":"magicBox.getProductDefinition",
				"session":self.SessionID,
				"params": None,
				"id":self.ID
				}

			self.SendCall(query_args,multicall=True)

			query_args = {
				"method":"magicBox.getSystemInfo",
				"session":self.SessionID,
				"params": None,
				"id":self.ID
				}

			self.SendCall(query_args,multicall=True)

			query_args = {
				"method":"magicBox.getMemoryInfo",
				"session":self.SessionID,
				"params": None,
				"id":self.ID
				}

			data = self.SendCall(query_args,multicall=True,multicallsend=True)
			if data == False:
				return

			if data.get('magicBox.getSoftwareVersion').get('result') and data.get('magicBox.getProductDefinition').get('result'):
				tmp = data.get('magicBox.getProductDefinition').get('params').get('definition')

				log.success("\033[92m[\033[91mSystem\033[92m]\033[0m\nVendor: {}, Build: {}, Version: {}\nDevice: {}, Web: {}, OEM: {}\nPackage: {}".format(
					tmp.get('Vendor',"(null)"),
					tmp.get('BuildDateTime',"(null)"),
					data.get('magicBox.getSoftwareVersion').get('params').get('version').get('Version',"(null)"),
					tmp.get('Device',"(null)"),
					tmp.get('WebVersion',"(null)"),
					tmp.get('OEMVersion',"(null)"),
					tmp.get('PackageBaseName',"(null)") if tmp.get('PackageBaseName') else tmp.get('ProductName',"(null)"),
					))

			if data.get('magicBox.getSystemInfo').get('result'):
				tmp = data.get('magicBox.getSystemInfo').get('params')
				log.success("\033[92m[\033[91mDevice\033[92m]\033[0m\nType: {}, CPU: {}, HW ver: {}, S/N: {}".format(
					tmp.get('deviceType',"(null)"),
					tmp.get('processor',"(null)"),
					tmp.get('hardwareVersion',"(null)"),
					tmp.get('serialNumber',"(null)"),
					))

			if data.get('magicBox.getMemoryInfo').get('result'):
				tmp = data.get('magicBox.getMemoryInfo').get('params')
				log.success("\033[92m[\033[91mMemory\033[92m]\033[0m\nTotal: {}, Free: {}".format(
					size(tmp.get('total',0)),
					size(tmp.get('free',0))
					))
			self.devStorage()
			self.getEncryptInfo()

		elif cmd[0] == 'certificate':
			query_args = {
				"method":"CertManager.exportRootCert",
				"session":self.SessionID,
				"params": None,
				"id":self.ID
				}

			self.SendCall(query_args,multicall=True)

			query_args = {
				"method":"CertManager.getSvrCertInfo",
				"session":self.SessionID,
				"params": None,
				"id":self.ID
				}

			data = self.SendCall(query_args,multicall=True,multicallsend=True)

			if data == False:
				return

			if data.get('CertManager.exportRootCert').get('result'):
				CACERT = base64.decodebytes(data.get('CertManager.exportRootCert').get('params').get('cert').encode('latin-1'))
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
				modn = x509.get_pubkey().to_cryptography_key().public_numbers().n
				print('{:X}'.format(modn))
			else:
				log.failure("\033[92m[\033[91mRoot Certificate\033[92m]\033[0m\n{}".format(color(data.get('CertManager.exportRootCert').get('error'),LRED)))
				return False

			if data.get('CertManager.getSvrCertInfo').get('result'):
				log.success("\033[92m[\033[91mServer Certificate\033[92m]\033[0m\n{}".format(
					json.dumps(data.get('CertManager.getSvrCertInfo'),indent=4),
					))

		elif cmd[0] == 'dhp2p':

			query_args = {
				"method":"Nat.getTurnStatus",
				"session":self.SessionID,
				"params": None,
				"id":self.ID
				}
			self.SendCall(query_args,multicall=True)

			query_args = {
				"method":"magicBox.getSystemInfo",
				"session":self.SessionID,
				"params": None,
				"id":self.ID
				}

			self.SendCall(query_args,multicall=True)

			query_args = {
				"id":self.ID,
				"method":"configManager.getConfig",
				"params": {
					"name":"_DHCloudUpgrade_",
					},
				"session":self.SessionID
				}
			self.SendCall(query_args,multicall=True)

			query_args = {
				"id":self.ID,
				"method":"configManager.getConfig",
				"params": {
					"name":"_DHCloudUpgradeRecord_",
					},
				"session":self.SessionID
				}
			data = self.SendCall(query_args,multicall=True,multicallsend=True)
			if data == False:
				return

			if data.get('Nat.getTurnStatus').get('result'):
				tmp = data.get('Nat.getTurnStatus').get('params').get('Status')
				log.success("\033[92m[\033[91mDH DMSS P2P\033[92m]\033[0m\nEnable: {}, Status: {}, Detail: {}".format(
					tmp.get('IsTurnChannel',"(null)"),
					tmp.get('Status',"(null)"),
					tmp.get('Detail',"(null)"),
				))

			if data.get('_DHCloudUpgradeRecord_').get('result') or data.get('_DHCloudUpgrade_').get('result'):

				tmp = data.get('_DHCloudUpgradeRecord_').get('params').get('table')
				tmp2 = data.get('_DHCloudUpgrade_').get('params').get('table')
				log.success("\033[92m[\033[91mDH Cloud Firmware Upgrade\033[92m]\033[0m\nAddress: {}, Port: {}, ProxyAddr: {}, ProxyPort: {}\nAutoCheck: {}, CheckInterval: {}, Upgrade: {}, downloadState: {}\nLastVersion: {},\nLastSubVersion: {}\npackageId: {}".format(
					tmp2.get('Address'),
					tmp2.get('Port'),

					tmp.get('ProxyAddr'),
					tmp.get('ProxyPort'),
					bool(tmp.get('AutoCheck')),
					tmp.get('CheckInterval'),
					bool(tmp.get('Upgrade')),
					bool(tmp.get('downloadState')),
					tmp.get('LastVersion'),
					tmp.get('LastSubVersion'),
					tmp.get('packageId'),
				))

			if data.get('magicBox.getSystemInfo').get('result'):
				tmp = data.get('magicBox.getSystemInfo').get('params')
				log.success("\033[92m[\033[91mDH Cloud Firmware ID\033[92m]\033[0m\nUpgrade S/N: {}\nUpdate S/N: {}".format(
					tmp.get('updateSerialCloudUpgrade',"(null)"),
					tmp.get('updateSerial',"(null)"),
				))


	#
	# PoC for new non-existing configuration
	# (InstanceService() not really needed here, more as FYI for future)
	#

	def newConfig(self,msg):

		cmd = msg.split()

		Usage = {
			"show":"(Show config in script)",
			"set":"(Set config in device)",
			"get":"(Get config from device)",
			"del":"(Delete config in device)",
		}
		if len(cmd) == 1 or len(cmd) == 2 and cmd[1] == '-h':
			log.info('{}'.format(helpAll(msg=msg,Usage=Usage)))
			return True

		methodName = 'configManager'
		self.InstanceService(methodName,start=True)
		OBJECT = self.InstanceService(methodName,pull='object')

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
				"object":OBJECT,
				"session":self.SessionID,
				"id":self.ID
				}
			if cmd[1] == 'show':
				print(json.dumps(query_args,indent=4))
				return


			log.info("query: {} ".format(query_args))

			data = self.SendCall(query_args)
			if data == False:
				return
			print(json.dumps(data,indent=4))

		elif cmd[1] == 'get':
			query_args = {
				"method":"configManager.getConfig",
				"params": {
					"name":"Config_31337",
					},
				"object":OBJECT,
				"session":self.SessionID,
				"id":self.ID
				}

			log.info("query: {} ".format(query_args))

			data = self.SendCall(query_args)
			if data == False:
				return

			print(json.dumps(data,indent=4))

		elif cmd[1] == 'del':
			query_args = {
				"method":"configManager.deleteConfig",
				"params": {
					"name":"Config_31337",
					},
				"object":OBJECT,
				"session":self.SessionID,
				"id":self.ID
				}

			log.info("query: {} ".format(query_args))

			data = self.SendCall(query_args)
			if data == False:
				return

			print(json.dumps(data,indent=4))

		else:
			log.info('{}'.format(helpAll(msg=msg,Usage=Usage)))
			return True

		self.InstanceService(methodName,stop=True)

		return

	def setDebug(self,msg):

		cmd = msg.split()

		methodName = 'configManager'

		self.InstanceService(methodName,start=True)
		OBJECT = self.InstanceService(methodName,pull='object')
		if not OBJECT:
			return False

		query_args = {
			"method":"configManager.setConfig",
				"params": {
				"name":"Debug",
					"table": {
						"PrintLogLevel":0,
#						"enable":True,
						},
				},
			"object":OBJECT,
			"session":self.SessionID,
			"id":self.ID
			}

		data = self.SendCall(query_args)
		if data == False:
			return False

		log.success("PrintLogLevel 0: {}".format(data.get('result')))

		query_args = {
			"method":"configManager.setConfig",
				"params": {
				"name":"Debug",
					"table": {
						"PrintLogLevel":6,
#						"enable":True,
						},
				},
			"object":OBJECT,
			"session":self.SessionID,
			"id":self.ID
			}

		data = self.SendCall(query_args)
		if data == False:
			return False

		log.success("PrintLogLevel 6: {}".format(data.get('result')))

		self.InstanceService(methodName,stop=True)

		return True

	def uBoot(self,msg):

		cmd = msg.split()

		Usage = {
			"printenv":"(Get all possible env config)",
			"setenv":"<variable> <value> (not working)",
			"getenv":"<variable>"
		}
		if len(cmd) == 1:
			log.info('{}'.format(helpAll(msg=msg,Usage=Usage)))
			return True

		methodName = 'magicBox'

		self.InstanceService(methodName,start=True)
		OBJECT = self.InstanceService(methodName,pull='object')
		if not OBJECT:
			return False

		if cmd[1] == 'setenv':
			if not len(cmd) == 4:
				log.info('{}'.format(helpAll(msg=msg, Usage=Usage)))
				return True

			query_args = {
				"method":"magicBox.setEnv",
				"params": {
					"name":cmd[2],
					"value":cmd[3],
				},
				"object":OBJECT,
				"session":self.SessionID,
				"id":self.ID
				}

		#
		# Here we looking for the most common U-Boot enviroment variables, if you miss any, add it to the list here.
		#
		elif cmd[1] == 'printenv': # OK: IPC/VTH/VTO, NOT: NVR

			query_args = {
				"method":"magicBox.getBootParameter",
				"params": {
					"names":[
						"algorithm",
						"appauto",
						"AUTHCODE",
						"authcode",
						"AUTHKEY",
						"autogw",
						"autolip",
						"autoload",
						"autonm",
						"autosip",
						"baudrate",
						"bootargs",
						"bootcmd",
						"bootdelay",
						"bootfile",
						"BSN",
						"coremnt",
						"COUNTRYCODE",
						"da",
						"da0",
						"dc",
						"debug",
						"devalias",
						"DeviceID",
						"deviceid",
						"DeviceSecret",
						"DEVID",
						"devname",
						"devOEM",
						"dh_keyboard",
						"dk",
						"dl",
						"dp",
						"dr",
						"DspMem",
						"du",
						"dvname",
						"dw",
						"encrypbackup",
						"eth1addr",
						"ethact",
						"ethaddr",
						"ext1",
						"ext2",
						"ext3",
						"ext4",
						"ext5",
						"fd",
						"fdtaddr",
						"fileaddr",
						"filesize",
						"gatewayip",
						"HWID",
						"hwidEx",
						"HWMEM",
						"hxapppwd",
						"icrtest",
						"icrtype",
						"ID",
						"intelli",
						"ipaddr",
						"key",
						"licence",
						"loglevel",
						"logserver",
						"MarketArea",
						"mcuDebug",
						"mcuHWID",
						"mdcmdline",
						"Mem512M",
						"mmc_root",
						"mp_autotest",
						"nand_root",
						"netmask",
						"netretry",
						"OEI",
						"partitions",
						"PartitionVer",
						"peripheral",
						"ProductKey",
						"ProductSecret",
						"quickstart",
						"randomcode",
						"restore",
						"SC",
						"ser_debug",
						"serverip",
						"setargs_mmc",
						"setargs_nand",
						"setargs_spinor",
						"SHWID",
						"Speripheral",
						"spinand_root",
						"spinor_root",
						"stderr",
						"stdin",
						"stdout",
						"sysbackup",
						"SysMem",
						"tftptimeout",
						"tk",
						"TracingCode",
						"tracode",
						"uid",
						"up",
						"updatetimeout",
						"UUID",
						"vendor",
						"ver",
						"Verif_Code",
						"verify",
						"videodebug",
						"watchdog",
						"wifiaddr",

						"HWID_ORG", # MCW
						],
				},
				"object":OBJECT,
				"session":self.SessionID,
				"id":self.ID
			}

		elif cmd[1] == 'getenv':
			if not len(cmd) == 3:
				log.info('{}'.format(helpAll(msg=msg, Usage=Usage)))
				return True
#			method = "magicBox.getEnv"					# should be
			method = "magicBox.getBootParameter"		# working too
			query_args = {
				"method":method,
				"params": {
					"names":[cmd[2]],					# needed for magicBox.getBootParameter
#					"name":cmd[2],						# needed for magicBox.getEnv
				},
				"object":OBJECT,
				"session":self.SessionID,
				"id":self.ID
				}
		else:
			log.info('{}'.format(helpAll(msg=msg,Usage=Usage)))
			return True

		data = self.SendCall(query_args,errorcodes=True)
		if not data:
			return False
		if data.get('result'):
			print(json.dumps(data,indent=4))
		elif not data.get('result'):
			log.failure('Error: {}'.format(data.get('error')))

		self.InstanceService(methodName,stop=True)

		return

	#
	# Device discovery - by remote device
	#
	def deviceDiscovery(self,msg,callback=False):

		if callback:
			data = msg
			print(json.dumps(data,indent=4))
			return True

		cmd = msg.split()

		Usage = {
			"stop":"(stop)",
			"multicast":"(Discover devices with Multicast)",
			"arpscan":{
				"<ipBegin> <ipEnd>":"(Discover devices with ARP)"
				},
			"refresh":"(<Undefined> Not working)",
			"scan":"(<Undefined> Not working)",
			"setconfig":"(<Undefined> Not working)",
		}

		if len(cmd) == 1 or cmd[1] == '-h':
			log.info('{}'.format(helpAll(msg=msg,Usage=Usage)))
			return True

		methodName = 'deviceDiscovery'

		if cmd[1] == 'stop':

			OBJECT = self.InstanceService(methodName,fuzz=True,pull='object')
			if not OBJECT:
				log.failure('{}: Error!'.format(methodName))
				return False

			query_args = {
				"id":self.ID,
				"method":"deviceDiscovery.stop",
				"params": None,
				"object":OBJECT,
				"session":self.SessionID
				}

			data = self.SendCall(query_args)
			if not data:
				return

			if not self.InstanceService(methodName,stop=True):
				return False

			return True

		elif cmd[1] == 'multicast':

			if not self.InstanceService(methodName,pull='object'):
				self.InstanceService(methodName,attach=True,start=True)
			OBJECT = self.InstanceService(methodName,fuzz=True,pull='object')
			if not OBJECT:
				log.failure('{}: Error!'.format(methodName))
				return False

			query_args = {
				"id":self.ID,
				"method":"deviceDiscovery.start",
				"params": {
					"timeout":"15",
					},
				"object":OBJECT,
				"session":self.SessionID
				}

		elif cmd[1] == 'arpscan':

			if not len(cmd) == 4:
				log.info('{}'.format(helpAll(msg=msg,Usage=Usage)))
				return False
			ipBegin = cmd[2]
			ipEnd = cmd[3]

			if not util.CheckIP(cmd[2]):
				log.failure('"{}" is not valid ipAddr'.format(cmd[3]))
				return False
			if not util.CheckIP(cmd[3]):
				log.failure('"{}" is not valid ipAddr'.format(cmd[3]))
				return False

			if not self.InstanceService(methodName,pull='object'):
				self.InstanceService(methodName,attach=True,start=True)
			OBJECT = self.InstanceService(methodName,fuzz=True,pull='object')
			if not OBJECT:
				log.failure('{}: Error!'.format(methodName))
				return False


			query_args = {
				"id":self.ID,
				"method":"deviceDiscovery.ipScan",
				"params": {
					"ipBegin":ipBegin,
					"ipEnd":ipEnd,
					"timeout":"1",
					},
				"object":OBJECT,
				"session":self.SessionID
				}

		elif cmd[1] == 'refresh':
			if not self.InstanceService(methodName,pull='object'):
				self.InstanceService(methodName,attach=True,start=True)
			OBJECT = self.InstanceService(methodName,fuzz=True,pull='object')
			if not OBJECT:
				log.failure('{}: Error!'.format(methodName))
				return False

			query_args = {
				"id":self.ID,
				"method":"deviceDiscovery.refresh",
				"params": {
					"device":None,
#					"timeout":5,
#					"device":"eth2",
#					"object":OBJECT,
					},
				"object":OBJECT,
				"session":self.SessionID
				}

		elif cmd[1] == 'scan':	# (pthread) error: {'code': 268632080, 'message': ''}

			if not self.InstanceService(methodName,pull='object'):
				self.InstanceService(methodName,attach=True,start=True)
			OBJECT = self.InstanceService(methodName,fuzz=True,pull='object')
			if not OBJECT:
				log.failure('{}: Error!'.format(methodName))
				return False

			query_args = {
				"id":self.ID,
				"method":"deviceDiscovery.scanDevice",
				"params": {
					"ip":["192.168.5.21"],
					"timeout":10,
					},
				"object":OBJECT,
				"session":self.SessionID
				}

		elif cmd[1] == 'setconfig':	# not complete

			if not self.InstanceService(methodName,pull='object'):
				self.InstanceService(methodName,attach=True,start=True)
			OBJECT = self.InstanceService(methodName,fuzz=True,pull='object')
			if not OBJECT:
				log.failure('{}: Error!'.format(methodName))
				return False

			query_args = {
				"id":self.ID,
				"method":"deviceDiscovery.setConfig",
				"params": {
					"mac":"a0:bd:de:ad:be:ef",
					"username":"admin",
					"password":"admin", # shall be encrypted
					"devConfig":{"DummyConfig":""}, # Needs to figure right params
					},
				"object":OBJECT,
				"session":self.SessionID
				}

		else:
			log.info('{}'.format(helpAll(msg=msg,Usage=Usage)))
			return True

		data = self.SendCall(query_args,errorcodes=True)
		if data.get('result'):
			print(json.dumps(data,indent=4))
		else:
			self.InstanceService(methodName,stop=True)
			log.failure('{}: {}'.format(query_args.get('method'),data.get('error')))

		return

	#
	# tcpdump network capture from remote device
	#
	def NetworkSnifferManager(self,msg):

		cmd = msg.split()

		Usage = {
			"start":{
				"<nic> <path>":"[Wireshark capture filter syntax]"
				},
			"stop":"(stop remote pcap)",
			"info":"(info about remote pcap)"
		}
		if len(cmd) == 1 or cmd[1] == 'start' and not len(cmd) >= 4 or cmd[1] == '-h':
			log.info('{}'.format(helpAll(msg=msg,Usage=Usage)))
			return True

		methodName = 'NetworkSnifferManager'
		if not self.InstanceService(methodName,pull='object'):
			self.InstanceService(methodName,start=True)
		OBJECT = self.InstanceService(methodName,pull='object')
		if not OBJECT:
			return False

		self.NIC = 'eth0'

#		NIC = "eth0"
#		PATH = "/nfs"
#		FILTER = ""
#		FILTER = "not host 192.168.57.20 and not host 192.168.57.7 and not host 192.168.57.167 and not host 192.168.57.27"

		if cmd[1] == 'start':


			if not self.InterimRemoteDiagnose("diag nfs status"):
				log.failure("NFS must be mounted with: diag nfs mount")
				return False

			self.NIC = cmd[2]
			PATH = cmd[3]
			FILTER = ''
			if len(cmd) > 3:
				FILTER = ' '.join(cmd[4:])

			query_args = {
				"id":self.ID,
				"method":"NetworkSnifferManager.start",
				"params": {
					"networkCard":self.NIC,
					"path":PATH,
					"saveType":"Wireshark/Tcpdump",
					"filter":FILTER,
					},
				"object":OBJECT,
				"session":self.SessionID
				}

			data = self.SendCall(query_args)
			if data == False:
				log.failure(color("{}: {}".format( query_args.get('method'),data),LRED))
				return False

			if not data.get('result'):
				log.failure(color("{}: {}".format( query_args.get('method'),data),LRED))
				self.InstanceService(methodName,stop=True)
				return False

			self.networkSnifferID = data.get('params').get('networkSnifferID')
			log.info("({}) Start: ID: {}, NIC: {}, Path: {}, Filter: {}".format(
				cmd[0],
				self.networkSnifferID,
				query_args.get('params').get('networkCard'),
				query_args.get('params').get('path'),
				query_args.get('params').get('filter'),
				))

		elif cmd[1] == 'info':

			query_args = {
				"id":self.ID,
				"method":"NetworkSnifferManager.getSnifferInfo",
				"params":{
					"condition": {
						"NetworkCard":self.NIC,
						},
				}, 
				"session":self.SessionID,
				"object":OBJECT,
				}

			data = self.SendCall(query_args)
			if data == False:
				log.failure(color("{}: {}".format( query_args.get('method'),data),LRED))
				return False

			if not data.get('result'):
				log.failure(color("{}: {}".format( query_args.get('method'),data),LRED))
				self.InstanceService(methodName,stop=True)
				return False

			snifferInfos = data.get('params').get('snifferInfos')
			if not len(snifferInfos):
				log.info("No remote pcap running")
				return False

			self.networkSnifferID = snifferInfos[0].get('NetworkSnifferID')
			self.networkSnifferPath = snifferInfos[1].get('Path')
			log.info("({}) Info: ID: {}, Path: {}".format(cmd[0], self.networkSnifferID, self.networkSnifferPath))

			return True

		elif cmd[1] == 'stop':

			if not self.NetworkSnifferManager("pcap info"):
				return False

			query_args = {
				"id":self.ID,
				"method":"NetworkSnifferManager.stop",
				"params":{
					"networkSnifferID":self.networkSnifferID,
				}, 
				"session":self.SessionID,
				"object":OBJECT,
				}

			data = self.SendCall(query_args)
			if data == False:
				log.failure(color("{}: {}".format( query_args.get('method'),data),LRED))
				return False

			if not data.get('result'):
				log.failure(color("{}: {}".format( query_args.get('method'),data),LRED))
				self.InstanceService(methodName,stop=True)
				return False

			self.InstanceService(methodName,stop=True)
			log.info("({}) Stopped: ID: {}, Path: {}".format(cmd[0], self.networkSnifferID, self.networkSnifferPath))

		else:
			log.info('{}'.format(helpAll(msg=msg,Usage=Usage)))

		return

	#
	# Debug of remote device
	#
	def InterimRemoteDiagnose(self,msg):

		cmd = msg.split()

		Usage = {
			"nfs":{
				"status":"(Check if NFS mounted)",
				"mount":"[<server ipAddr> /<server path>]",
				"umount":"(Umount NFS)",
				},
			"usb":{
				"get":"(Not done yet)",
				"set":"(Not done yet)",
			},
			"pcap":{
				"start":"(Start capture)",
				"stop":"(Stop capture)",
				"filter":"<get> | <set> <lo|eth0|eth2> <ipAddr>",
			},
			"coredump":{
				"start":"(Start coredump support)",
				"stop":"(Stop coredump support)",
			},
			"logs":{
				"start":"(Start redirect logs to NFS)",
				"stop":"(Stop redirect logs to NFS)",
			}
		}
		if len(cmd) < 2 or len(cmd) == 3 and cmd[1] == '-h':
			log.info('{}'.format(helpAll(msg=msg,Usage=Usage)))
			return True

		if not self.CheckForService('InterimRemoteDiagnose'):
			return False

		if cmd[1] == 'nfs':

			if not len(cmd) >= 3:
				log.info('{}'.format(helpAll(msg=msg, Usage=Usage)))
				return True

			if cmd[2] == 'status':

				query_args = {
					"id":self.ID,
					"method": "InterimRemoteDiagnose.getConfig", 
					"params":{
						"name":"InterimRDNfs",
						},
					"session":self.SessionID
					}
				data = self.SendCall(query_args)
				if not data == False:
					data = data.get('params').get('DebugConfig')
					log.info("NFS Directory: {}, Serverip: {}, Enable: {}".format(data.get('Directory'),data.get('Serverip'),data.get('Enable')))

				query_args = {
					"id":self.ID,
					"method": "InterimRemoteDiagnose.testNfsStatus", 
					"params":{
						},
					"session":self.SessionID
					}
				data = self.SendCall(query_args)
				if not data == False:
					log.info("NFS connected: {}".format(data.get('params').get('conn')))
					return data.get('params').get('conn')

				return False

			elif cmd[2] == 'mount' or cmd[2] == 'umount':

				if len(cmd) >= 4:
					if not util.CheckIP(cmd[3]):
						log.failure('"{}" is not valid ipAddr'.format(cmd[3]))
						return False
					if len(cmd) == 5 and not cmd[4][0] == '/':
						log.failure('path must start with "/"'.format(cmd[4]))
						return False

				query_args = {
					"id":self.ID,
					"method": "InterimRemoteDiagnose.getConfig", 
					"params":{
						"name":"InterimRDNfs",
						},
					"session":self.SessionID
					}
				data = self.SendCall(query_args)
				if not data:
					return False
				DebugConfig = data.get('params').get('DebugConfig')

				DebugConfig['Enable'] = True if cmd[2] == 'mount' else False
				DebugConfig.update({"Serverip":cmd[3] if len(cmd) >= 4 else DebugConfig.get('Serverip')})
				DebugConfig.update({"Directory":cmd[4] if len(cmd) == 5 else DebugConfig.get('Directory')})

				query_args = {
					"id":self.ID,
					"method": "InterimRemoteDiagnose.setConfig",
					"params":{
						"name":"InterimRDNfs",
						"DebugConfig":{
							# Default config
#							"Directory":"/c/public_dev",
#							"Enable":False,
#							"Serverip":"10.33.12.137"
							},
						},
					"session":self.SessionID
					}
				query_args.get('params').get('DebugConfig').update(DebugConfig)

				data = self.SendCall(query_args)
				if not data:
					return False
				log.info("NFS {}: {}".format('mount' if cmd[2] == 'mount' else 'umount',data.get('result')))
				return True
			else:
				log.info('{}'.format(helpAll(msg=msg,Usage=Usage)))
				return True

		elif cmd[1] == 'usb':

			if not len(cmd) == 3:
				log.info('{}'.format(helpAll(msg=msg, Usage=Usage)))
				return True

			if cmd[2] == 'get':

				query_args = {
					"id":self.ID,
					"method": "InterimRemoteDiagnose.getUStoragePosition", 
					"params":{
						},
					"session":self.SessionID
					}
				data = self.SendCall(query_args)
				if not data:
					return False
				log.info("USB Storage: {}".format(data.get('params').get('UStoragePosition') if data.get('params').get('UStoragePosition') else "Not found"))
				return True

			elif cmd[2] == 'set':

				query_args = {
					"id":self.ID,
					"method": "InterimRemoteDiagnose.setUStoragePosition", 
					"params":{
						"UStoragePosition":"/dev/sdb1",
						},
					"session":self.SessionID
					}
				data = self.SendCall(query_args)
				if not data:
					return False
				log.info("USB Storage: {}".format(data))
				return True
			else:
				log.info('{}'.format(helpAll(msg=msg,Usage=Usage)))
				return False

		elif cmd[1] == 'pcap':

			if not len(cmd) >= 3:
				log.info('{}'.format(helpAll(msg=msg, Usage=Usage)))
				return True

			if cmd[2] == 'filter':
				if not len(cmd) >= 4:
					log.info('{}'.format(helpAll(msg=msg, Usage=Usage)))
					return False

				if cmd[3] == 'get':
					query_args = {
						"id":self.ID,
						"method": "InterimRemoteDiagnose.getConfig",
						"params":{
							"name":"InterimRDNetFilter",
							},
						"session":self.SessionID
						}
					data = self.SendCall(query_args)
					if data == False:
						return False
					log.info("PCAP Filter: {}".format(data.get('params').get('DebugConfig')))
					return True

				elif cmd[3] == 'set':

					#
					# Might be more data in the future, read and update only what we know
					# Leave possible other untouched
					#
	
					query_args = {
						"id":self.ID,
						"method": "InterimRemoteDiagnose.getConfig",
						"params":{
							"name":"InterimRDNetFilter",
							},
						"session":self.SessionID
						}
					data = self.SendCall(query_args)
					if not data:
						return False

					Name = 'eth0'
					FilterIP = ''

					# Default
#					Name = 'eth0'
#					FilterIP = '10.33.12.137'
#					FilterPort = '37777'

					DebugConfig = data.get('params').get('DebugConfig')
					DebugConfig.update({"FilterIP":FilterIP})
#					DebugConfig.update({"FilterPort":FilterPort})	# Cannot be changed from 37777
					DebugConfig.update({"Name":Name})

					query_args = {
						"id":self.ID,
						"method": "InterimRemoteDiagnose.setConfig",
						"params":{
							"name":"InterimRDNetFilter",
							"DebugConfig":DebugConfig,
							},
						"session":self.SessionID
						}
					data = self.SendCall(query_args)
					if not data:
						return False
					log.info("PCAP Filter: {}".format(DebugConfig))
					return True


			elif cmd[2] == 'start':

				if not self.InterimRemoteDiagnose("diag nfs status"):
					log.failure("NFS must be mounted with: diag nfs mount")
					return False

				query_args = {
					"id":self.ID,
					"method": "InterimRemoteDiagnose.getConfig",
					"params":{
						"name":"InterimRDNetFilter",
						},
					"session":self.SessionID
					}
				data = self.SendCall(query_args)
				if not data:
					return False

				log.info("PCAP Filter: {}".format(data.get('params').get('DebugConfig')))

				query_args = {
					"id":self.ID,
					"method":"InterimRemoteDiagnose.startRemoteCapture",	# {"result":true,"params":null,"session":336559066,"id":4}
					"params":{
						},
					"session":self.SessionID
					}
				data = self.SendCall(query_args)
				if not data:
					return False
				log.info("PCAP Start: {}".format(data.get('result')))
				return True

			elif cmd[2] == 'stop':
				query_args = {
					"id":self.ID,
					"method":"InterimRemoteDiagnose.stopRemoteCapture",		# {"result":true,"params":null,"session":468902923,"id":4}
					"params":{
						},
					"session":self.SessionID
					}
				data = self.SendCall(query_args)
				if not data:
					return False
				log.info("PCAP Stop: {}".format(data.get('result')))
				return True
			else:
				log.info('{}'.format(helpAll(msg=msg,Usage=Usage)))
				return True

		elif cmd[1] == 'coredump':

			if not args.force:
				log.failure("({}) will reboot NVR (force with -f)".format(cmd[1]))
				return False

			if not len(cmd) >= 3:
				log.info('{}'.format(helpAll(msg=msg, Usage=Usage)))
				return True

			if cmd[2] == 'start' or cmd[2] == 'stop':

				query_args = {
					"id":self.ID,
					"method": "InterimRemoteDiagnose.setConfig",
					"params":{
						"name":"InterimRDCoreDump",
						"DebugConfig": {
							"Enable":True if cmd[2] == 'start' else False,
							},
						},
					"session":self.SessionID
					}
				data = self.SendCall(query_args)
				if not data:
					return False
				log.info("CoreDump {}: {}".format("Start" if cmd[2] == 'start' else "Stop",data.get('result')))
				return True
			else:
				log.info('{}'.format(helpAll(msg=msg,Usage=Usage)))
				return False

		elif cmd[1] == 'logs':

			if not len(cmd) == 3:
				log.info('{}'.format(helpAll(msg=msg, Usage=Usage)))
				return True

			if not self.InterimRemoteDiagnose("diag nfs status"):
				log.failure("NFS must be mounted")
				return False

			if cmd[2] == 'start' or cmd[2] == 'stop':

				query_args = {
					"id":self.ID,
					"method": "InterimRemoteDiagnose.setConfig",
					"params":{
						"name":"InterimRDPrint",
						"DebugConfig": {
							"AlwaysEnable":False,
							"OnceEnable":True if cmd[2] == 'start' else False,
							"PrintLevel":6
							},
						},
					"session":self.SessionID
					}
				data = self.SendCall(query_args)
				if not data:
					return False
				log.info("Logs {}: {}".format("Start" if cmd[2] == 'start' else "Stop",data.get('result')))
				return True
			else:
				log.info('{}'.format(helpAll(msg=msg,Usage=Usage)))
				return True

		else:
			log.failure('No such command: {}'.format(msg))
			return True


	#
	# Main function for subscribe on events from device
	#
	def eventManager(self,msg):

		cmd = msg.split()

		Usage = {
			"1":"(enable)",
			"0":"(disable)"
		}

		if len(cmd) == 1 or cmd[1] == '-h':
			log.info('{}'.format(helpAll(msg=msg,Usage=Usage)))
			return True

		if not self.udp_server:
			if self.debugCalls:
				log.warning('Local UDP server not running')
			return False


		methodName = 'eventManager'
		codes = ["All"]

		if cmd[1] == '1':

			if self.InstanceService(methodName,pull='object'):
				log.failure("eventManager already enabled")
				return False

			self.eventManagerSetConfig(None)

			self.InstanceService(methodName,attachParams={"codes":codes},start=True)
			OBJECT = self.InstanceService(methodName,pull='object')
			if not OBJECT:
				return False

		elif cmd[1] == '0':

			if not self.InstanceService(methodName,pull='object'):
				log.failure("eventManager already disabled")
				return False

			self.eventManagerSetConfig(None)
			self.InstanceService(methodName,stop=True)

			return 

		else:
			log.info('{}'.format(helpAll(msg=msg,Usage=Usage)))
			return False

	#
	# Will dump remote config, scan for EventHandler() and enable disabled ones
	# Using setTemporaryConfig / restoreTemporaryConfig, so changes will not be permanent (in case of reboot)
	#
	def eventManagerSetConfig(self,msg):

		methodName = 'configManager'

		self.InstanceService(methodName,start=True)
		OBJECT = self.InstanceService(methodName,pull='object')
		if not OBJECT:
			return False

		idMap = {}

		if not self.InstanceService('eventManager',pull='object'):

			if not self.RemoteConfigCache:
				log.info("Caching remote config")
				query_args = {
					"method":"configManager.getConfig",
					"params": {
						"name":'All',
						},
					"session":self.SessionID,
					"id":self.ID
					}
				self.RemoteConfigCache = self.SendCall(query_args)
				if not self.RemoteConfigCache:
					return False

			configMembers = copy.deepcopy(self.RemoteConfigCache.get('params').get('table'))

			self.RestoreEventHandler = {}

			config = {}

			for member in configMembers:
				try:

					if isinstance(configMembers[member],list):
						for count in range(0,len(configMembers[member])):

							if configMembers[member][count].get('EventHandler'):

								if not configMembers[member][count].get('Enable'):
									self.RestoreEventHandler.update({
										member:configMembers[member],
										})
									config.update({member:configMembers[member]})
									config[member][count]['Enable'] = True

									query_args = {
										"method":"configManager.setTemporaryConfig",
											"params": {
												"name":member,
												"table": config[member],
											},
										"object":OBJECT,
										"session":self.SessionID,
										"id":self.ID
										}
									idMap.update({self.ID:member})
									self.SendCall(query_args, multicall=True)
								elif configMembers[member][count].get('Enable'):
									log.success('{}[{}]: Already enabled'.format(member,count))

							elif configMembers[member][count].get('CurrentProfile'): # CommGlobal

								if not configMembers[member][count].get('AlarmEnable') or not configMembers[member][0].get('ProfileEnable'):
									self.RestoreEventHandler.update({
										member:configMembers[member],
										})
									config.update({member:configMembers[member]})
									config[member][count]['AlarmEnable'] = True
									config[member][count]['ProfileEnable'] = True

									query_args = {
										"method":"configManager.setTemporaryConfig",
											"params": {
												"name":member,
												"table": config[member],
											},
										"object":OBJECT,
										"session":self.SessionID,
										"id":self.ID
										}
									idMap.update({self.ID:member})
									self.SendCall(query_args, multicall=True)
								elif configMembers[member][count].get('AlarmEnable'):
									log.success('{}[{}]: Already enabled'.format(member,count))


					elif isinstance(configMembers[member],dict):

						if 'EventHandler' in configMembers[member]:

							if not configMembers[member].get('Enable'):
								self.RestoreEventHandler.update({
								member:configMembers[member],
								})
								config.update({member:configMembers[member]})
								config[member]['Enable'] = True

								query_args = {
									"method":"configManager.setTemporaryConfig",
										"params": {
											"name":member,
											"table": config[member],
										},
									"object":OBJECT,
									"session":self.SessionID,
									"id":self.ID
									}
								idMap.update({self.ID:member})
								self.SendCall(query_args, multicall=True)
							elif configMembers[member].get('Enable'):
								log.success('{}: Already enabled'.format(member))

						elif 'AlarmEnable' in configMembers[member]: # CommGlobal

							if not configMembers[member].get('AlarmEnable') or not configMembers[member].get('ProfileEnable'):
								self.RestoreEventHandler.update({
								member:configMembers[member],
								})
								config.update({member:configMembers[member]})
								config[member]['AlarmEnable'] = True
								config[member]['ProfileEnable'] = True

								query_args = {
									"method":"configManager.setTemporaryConfig",
										"params": {
											"name":member,
											"table": config[member],
										},
									"object":OBJECT,
									"session":self.SessionID,
									"id":self.ID
									}
								idMap.update({self.ID:member})
								self.SendCall(query_args, multicall=True)
							elif configMembers[member].get('AlarmEnable'):
								log.success('{}: Already enabled'.format(member))


				except (AttributeError, IndexError) as e:
					pass

			log.info("Enabling disabled events")
			data = self.SendCall(None, multicall=True,multicallsend=True)
			for ID in idMap:
				if data.get(ID).get('result'):
					log.success('{}: {}'.format(idMap.get(ID),data.get(ID).get('result')) )
				else:
					log.failure('{}: {}'.format(idMap.get(ID),data.get(ID).get('result')) )
			self.InstanceService(methodName,stop=True)
			return True

		elif self.InstanceService('eventManager',pull='object'):

			for member in self.RestoreEventHandler:
				query_args = {
					"method":"configManager.restoreTemporaryConfig",
						"params": {
							"name":member,
						},
					"object":OBJECT,
					"session":self.SessionID,
					"id":self.ID
					}
				idMap.update({query_args.get('id'):member})
				self.SendCall(query_args, multicall=True)

		log.info("Restoring event config")
		data = self.SendCall(None, multicall=True,multicallsend=True)

		for ID in idMap:
			if data.get(ID).get('result'):
				log.success('{}: {}'.format(idMap.get(ID),data.get(ID).get('result')) )
			else:
				log.failure('{}: {}'.format(idMap.get(ID),data.get(ID).get('result')) )

		self.InstanceService(methodName,stop=True)
		return


	def netApp(self,msg,callback=False):

		#
		# Should need to have events subscribed
		#
#		if callback:
#			print(json.loads(msg,indent=4))
#			return True

		cmd = msg.split()

		Usage = {
			"info":"(Network Information)",
			"wifi": {
				"enable":"(enable adapter)",
				"disable":"(disable adapter)",
				"scan":"(scan for WiFi AP)",
				"conn":"<SSID> <key>",
				"disc":"(disconnect from WiFi AP)",
				"reset":"(reset WiFi settings to default)",
			},
			"upnp": {
				"status":"(show UPnP status)",
				"enable":"[all] (enable UPnP)",
				"disable":'[all] (disable UPnP)'
			}
		}

		if not len(cmd) >= 2 or cmd[1] == '-h':
			log.info('{}'.format(helpAll(msg=msg,Usage=Usage)))
			return True

		methodName = 'netApp'

		if not self.InstanceService(methodName,pull='object'):
			self.InstanceService(methodName,start=True)

		OBJECT = self.InstanceService(methodName,pull='object')
		if not OBJECT:
			return False

		query_args = {
		"method":"netApp.getNetInterfaces",
			"params": {
			},
			"object":OBJECT,
			"session": self.SessionID,
			"id": self.ID
		}
		netInterface = self.SendCall(query_args)

		if cmd[1] == 'wifi':

			if not len(cmd) >= 3 or cmd[1] == '-h':
				log.info('{}'.format(helpAll(msg=msg, Usage=Usage)))
				self.InstanceService(methodName,stop=True)
				return True

			WirelessNIC = False

			for nic in netInterface.get('params').get('netInterface'):
				if nic.get('Type') == 'Wireless':
					WirelessNIC = nic.get('Name')

			if not WirelessNIC:
				log.failure("No WiFi adapter available")
				return False

			AuthEncr = {
				"00":"Off",
				"01":"WEP-OPEN",
				"11":"WEP-SHARED",
				"32":"WPA-PSK-TKIP",
				"33":"WPA-PSK-TKIP+AES",
				"34":"WPA-PSK-TKIP+AES",
				"42":"WPA2-TKIP",
				"52":"WPA2-PSK-TKIP",
				"53":"WPA2-PSK-AES",
				"54":"WPA2-PSK-TKIP+AES",
				"72":"WPA/WPA2-PSK-TKIP",
				"73":"WPA/WPA2-PSK-AES",
				"74":"WPA/WPA2-PSK-TKIP+AES",
			}
			LinkMode = {
				"0":"Auto",
				"1":"Ad-hoc",
				"2":"Infrastructure",
			}

			if len(cmd) == 3 and cmd[2] == 'scan':

				query_args = {
				"method":"netApp.scanWLanDevices",
					"params": {
						"Name":WirelessNIC,
						"SSID":"",
					},
					"object":OBJECT,
					"session": self.SessionID,
					"id": self.ID
				}
				data = self.SendCall(query_args)
				if not data.get('params').get('wlanDevice'):
					log.failure("No WiFi available")
					return False

				wlanDevice = data.get('params').get('wlanDevice')
				for AP in wlanDevice:
					log.success("BSSID: {} RSSI: {} Strength: {} Quality: {} Connected: {} SSID: {}\nMaxBitRate: {} Mbit NetWorkType: {} Connect Mode: {} Authorize Mode: {}".format(
						color(AP.get('BSSID'),GREEN),
						color(AP.get('RSSIQuality'),GREEN),
						color(AP.get('Strength'),GREEN),
						color(AP.get('LinkQuality'),GREEN),
						color(bool(AP.get('ApConnected')),GREEN if AP.get('ApConnected') else RED),
						color(AP.get('SSID'),GREEN),
						color(str(int(AP.get('ApMaxBitRate')) / 1000000).split('.')[0],GREEN),

						color(AP.get('ApNetWorkType'),GREEN),
						color(LinkMode.get(str(AP.get('LinkMode'))),GREEN),
						color(AuthEncr.get(str(AP.get('AuthMode')) + str(AP.get('EncrAlgr')),"UNKNOWN"),GREEN),
						))


			elif len(cmd) == 5 and cmd[2] == 'conn' or len(cmd) == 3 and cmd[2] == 'enable' or len(cmd) == 3 and cmd[2] == 'disable' or len(cmd) == 3 and cmd[2] == 'conn' or len(cmd) == 3 and cmd[2] == 'disc' or len(cmd) == 3 and cmd[2] == 'reset':

				if cmd[2] == 'conn' and len(cmd) == 5:

					query_args = {
					"method":"netApp.scanWLanDevices",
						"params": {
							"Name":WirelessNIC,
							"SSID":cmd[3],
						},
						"object":OBJECT,
						"session": self.SessionID,
						"id": self.ID
					}
					self.SendCall(query_args,multicall=True)

				query_args = {
					"method": "configManager.getDefault" if cmd[2] == 'reset' else "configManager.getConfig",
					"params": {
						"name": "WLan",
					},
					"session": self.SessionID,
					"id": self.ID
				}
				data = self.SendCall(query_args,multicall=True,multicallsend=True)
				if data == False:
					log.failure("(WLan) {}".format(data))
					return False

				WLan = data.get('WLan').get('params').get('table').get(WirelessNIC)

				if len(cmd) == 3 and cmd[2] == 'conn' or len(cmd) == 3 and cmd[2] == 'disc':
					if WLan.get('SSID'):
						if nic.get('ConnStatus') == 'Connected' and cmd[2] == 'conn':
							log.failure("Already Connected")
							return False
						elif nic.get('ConnStatus') == 'Disconn' and cmd[2] == 'disc':
							log.failure("Already Disconnected")
							return False
						elif not WLan.get('Enable'):
							log.failure("WiFi disabled")
							return False
						WLan['ConnectEnable'] = True if cmd[2] == 'conn' else False
					else:
						log.failure("Wireless not configured")
						return False
				elif len(cmd) == 3 and cmd[2] == 'enable' or len(cmd) == 3 and cmd[2] == 'disable':
					if WLan.get('Enable') and cmd[2] == 'enable':
						log.failure("Already Enabled")
						return False
					elif not WLan.get('Enable') and cmd[2] == 'disable':
						log.failure("Already Disabled")
						return False
					WLan['Enable'] = True if cmd[2] == 'enable' else False


				if cmd[2] == 'conn' and len(cmd) == 5:
					if not data.get('netApp.scanWLanDevices').get('result'):
						log.failure('Wrong SSID and/or AP not accessible')
						return False

					AP = data.get('netApp.scanWLanDevices').get('params').get('wlanDevice')[0]

					WLan['Encryption'] = AuthEncr.get(str(AP.get('AuthMode')) + str(AP.get('EncrAlgr'))) if cmd[2] == 'conn' else 'Off'
					WLan['LinkMode'] = LinkMode.get(str(AP.get('LinkMode')))
					WLan['ConnectEnable'] = True if cmd[2] == 'conn' else False
					WLan['KeyFlag'] = True if cmd[2] == 'conn' else False
					WLan['SSID'] = AP.get('SSID') if cmd[2] == 'conn' else ''
					WLan['Keys'][0] = cmd[4] if cmd[2] == 'conn' else 'abcd'

				query_args = {
					"method":"configManager.setConfig",
						"params": {
						"name":"WLan",
							"table": data.get('WLan').get('params').get('table'),
						},
					"session":self.SessionID,
					"id":self.ID
					}

				data = self.SendCall(query_args)

				if not data or not data.get('result'):
					log.failure('TimeOut for "{}" (wrong pwd?)'.format(WLan.get('SSID')))
					log.failure("data: {}".format(data))
					return False

				if cmd[2] == 'conn' and WLan.get('Enable') or cmd[2] == 'enable' and WLan.get('SSID') and WLan.get('ConnectEnable'):
					conn = log.progress("Status")

					while True:
						query_args = {
						"method":"netApp.getNetInterfaces",
							"params": {
							},
							"object":OBJECT,
							"session": self.SessionID,
							"id": self.ID
						}
						data = self.SendCall(query_args)

						for nic in data.get('params').get('netInterface'):
							if not nic.get('Type') == 'Wireless':
								continue
							conn.status(nic.get('ConnStatus'))
							if nic.get('ConnStatus') == 'Connected':
								conn.success('Connected')
								return True
							time.sleep(1)
				else:
					self.InstanceService(methodName,stop=True)
					log.success("Success")

			else:
				log.info('{}'.format(helpAll(msg=msg,Usage=Usage)))
				return True

		elif cmd[1] == 'info':

			for nic in netInterface.get('params').get('netInterface'):

				netAppmethod = {
					"netApp.getNetDataStat",
					"netApp.getNetResourceStat",
					"netApp.getCaps",
				}

				for method in netAppmethod:
					query_args = {
						"method": method,
						"params": {
							"Name":nic.get('Name'),
						},
						"object":OBJECT,
						"session": self.SessionID,
						"id": self.ID
					}
					self.SendCall(query_args,multicall=True)

				query_args = {
					"method": "configManager.getConfig",
					"params": {
						"name": "Network",
					},
					"session": self.SessionID,
					"id": self.ID
				}

				data = self.SendCall(query_args,multicall=True,multicallsend=True)

				NetDataStat = data.get('netApp.getNetDataStat').get('params')
				NetResourceStat = data.get('netApp.getNetResourceStat').get('params')
				IP = data.get('Network').get('params').get('table').get(nic.get('Name'))

				LinkInfo = "Link support long PoE: {}, connection: {}, speed: {}".format(
					nic.get('SupportLongPoE'),
					nic.get('Type') if nic.get('Type') == 'Wireless' else 'Wired',
					nic.get('Speed'),
					)

				log.success("\033[92m[\033[91m{}\033[92m]\033[0m {}{}\ndhcp: {} dns: [{}] mtu: {}\ninet {} netmask {} gateway {}\nether {} txqueuelen {}\nRX packets {} bytes {} ({}) util {} Kbps\nRX errors {} dropped {} overruns {} frame {}\nTX packets {} bytes {} ({}) util {} Kbps\nTX errors {} dropped {} carrier {} collisions {}\n{}".format(
					nic.get('Name'),
					color(nic.get('ConnStatus'),GREEN if nic.get('ConnStatus') == 'Connected' else RED),
					color(" (SSID: {})".format(nic.get('ApSSID')) if nic.get('ConnStatus') == 'Connected' and nic.get('Type') == 'Wireless' else '',LBLUE),

					IP.get('DhcpEnable'),
					', '.join(str(x) for x in IP.get('DnsServers')),
					IP.get('MTU'),
					IP.get('IPAddress'),
					IP.get('SubnetMask'),
					IP.get('DefaultGateway'),
					IP.get('PhysicalAddress'),

					NetDataStat.get('Transmit').get('txqueuelen'),
					NetDataStat.get('Receive').get('packets'),
					NetDataStat.get('Receive').get('bytes'),
					size(NetDataStat.get('Receive').get('bytes')),
					NetDataStat.get('Receive').get('speed'),

					NetDataStat.get('Receive').get('errors'),
					NetDataStat.get('Receive').get('droped'),
					NetDataStat.get('Receive').get('overruns'),
					NetDataStat.get('Receive').get('frame'),

					NetDataStat.get('Transmit').get('packets'),
					NetDataStat.get('Transmit').get('bytes'),
					size(NetDataStat.get('Transmit').get('bytes')),
					NetDataStat.get('Transmit').get('speed'),

					NetDataStat.get('Transmit').get('errros'),	# consistent.. d0h!
					NetDataStat.get('Transmit').get('droped'),
					NetDataStat.get('Transmit').get('collisions'),
					NetDataStat.get('Transmit').get('txqueuelen'),
					LinkInfo,
					))

			NetResourceInfo = "IP Channel In: {}, Net Capability: {}, Net Remain: {}\nRemote Preview: {}, Send Capability: {}, Send Remain {}".format(
				NetResourceStat.get('IPChanneIn'),
				NetResourceStat.get('NetCapability'),
				NetResourceStat.get('NetRemain'),
				NetResourceStat.get('RemotePreview'),
				NetResourceStat.get('RemoteSendCapability'),
				NetResourceStat.get('RemoteSendRemain'),
				)

			log.success("\033[92m[\033[91mInfo\033[92m]\033[0m default nic: {}, hostname: {}, domain: {}\n{}".format(
				data.get('Network').get('params').get('table').get('DefaultInterface'),
				data.get('Network').get('params').get('table').get('Hostname'),
				data.get('Network').get('params').get('table').get('Domain'),
				NetResourceInfo,
				))

			self.InstanceService(methodName,stop=True)

		elif cmd[1] == 'upnp':

			if not len(cmd) == 3:
				log.info('{}'.format(helpAll(msg=msg, Usage=Usage)))
				self.InstanceService(methodName,stop=True)
				return False

			query_args = {
				"method": "netApp.getUPnPStatus",
				"params": None,
				"object":OBJECT,
				"session": self.SessionID,
				"id": self.ID
			}
			self.SendCall(query_args,multicall=True)

			query_args = {
				"method": "configManager.getConfig",
				"params": {
					"name": "UPnP",
				},
				"session": self.SessionID,
				"id": self.ID
			}
			data = self.SendCall(query_args,multicall=True,multicallsend=True)

			if not data.get('netApp.getUPnPStatus').get('result') or not data.get('UPnP').get('result'):
				log.failure('UPnP service not supported')
				return False

			if len(cmd) == 3 and cmd[2] == 'status':

				UPnPStatus = data.get('netApp.getUPnPStatus').get('params')
				UPnP = data.get('UPnP').get('params').get('table')
				UPnPMap = ''

				for MapTable in range(0,len(UPnP.get('MapTable'))):
					UPnPMap += "Enable: {} Internal Port: {:<6} External Port: {:<6} Protocol: {}:{} ServiceName: {:<4} Status: {}\n".format(
						UPnP.get('MapTable')[MapTable].get('Enable'),
						UPnP.get('MapTable')[MapTable].get('InnerPort'),
						UPnP.get('MapTable')[MapTable].get('OuterPort'),
						UPnP.get('MapTable')[MapTable].get('Protocol'),
						UPnP.get('MapTable')[MapTable].get('ServiceType'),
						UPnP.get('MapTable')[MapTable].get('ServiceName'),
						color(UPnPStatus.get('PortMapStatus')[MapTable],GREEN if UPnPStatus.get('PortMapStatus')[MapTable] == 'Failed' else RED),
						)
				log.success("\033[92m[\033[91mUPnP\033[92m]\033[0m\nEnable: {}, Mode: {}, Device Discover: {}\nStatus: {}, Working: {}, Internal IP: {}, external IP: {}\n\033[92m[\033[91mMaps\033[92m]\033[0m\n{}".format(
					color(UPnP.get('Enable'),RED if UPnP.get('Enable') else GREEN),
					UPnP.get('Mode'),
					UPnP.get('StartDeviceDiscover'),
					color(UPnPStatus.get('Status'),RED if UPnPStatus.get('Working') else GREEN),
					color(UPnPStatus.get('Working'),RED if UPnPStatus.get('Working') else GREEN),
					UPnPStatus.get('InnerAddress'),
					UPnPStatus.get('OuterAddress'),
					UPnPMap,
					))


			elif len(cmd) >= 3 and cmd[2] == 'disable' or cmd[2] == 'enable':

				query_args = {
					"method": "configManager.getConfig",
					"params": {
						"name": "UPnP",
					},
					"session": self.SessionID,
					"id": self.ID
				}
				data = self.SendCall(query_args)

				UPnP = data.get('params').get('table')

				if not UPnP.get('Enable') and cmd[2] == 'disable' or UPnP.get('Enable') and cmd[2] == 'enable':
					log.failure("UPnP already {}".format('disabled' if cmd[2] == 'disable' else 'enabled'))
					return False

				UPnP['Enable'] = False if cmd[2] == 'disable' else True

				if len(cmd) == 4 and cmd[3] == 'all':
					for map in range(0,len(UPnP.get('MapTable'))):
						UPnP['MapTable'][map]['Enable'] = False if cmd[2] == 'disable' else True

				query_args = {
					"method":"configManager.setConfig",
						"params": {
						"name":"UPnP",
							"table": UPnP,
						},
					"session":self.SessionID,
					"id":self.ID
					}
				data = self.SendCall(query_args)

				if data.get('result'):
					log.success("UPnP {}".format('disabled' if cmd[2] == 'disable' else 'enabled'))
				else:
					log.failure("UPnP NOT {}".format('disabled' if cmd[2] == 'disable' else 'enabled'))

			else:
				log.failure("{} {} {}".format(cmd[0],cmd[1],Usage.get(cmd[1],'(No help defined)')))
				return False

		else:
			log.info('{}'.format(helpAll(msg=msg,Usage=Usage)))

		self.InstanceService(methodName,stop=True)

		return

	def dlog(self,msg):

		cmd = msg.split()

		methodName = 'log'

		self.InstanceService(methodName,start=True)
		OBJECT = self.InstanceService(methodName,pull='object')
		if not OBJECT:
			return False

		COUNT = 20

		if len(cmd) == 2:
			try:
				COUNT = int(cmd[1])
			except ValueError as e:
				log.failure('({}) not valid number'.format(cmd[1]))
				return False

		query_args = {
		"method": "global.getCurrentTime",
			"params": None,
			"session": self.SessionID,
			"id": self.ID
		}

		data = self.SendCall(query_args)
		if not data.get('result'):
			log.failure('{} Failed'.format(query_args.get('method')))
			return False

		query_args = {
		"method":"log.startFind",
			"params": {
				"condition": {
					"StartTime":"1970-01-01 00:00:00", # Lets start from the beginning ,)
					"EndTime":data.get('params').get('time'),
					"Translate":True,
					"Order":"Descent",	# ok
					"Types":"",
				},
			},
			"object":OBJECT,
			"session": self.SessionID,
			"id": self.ID
		}
		data = self.SendCall(query_args)
		if not data.get('result'):
			log.failure('{} Failed'.format(query_args.get('method')))
			return False

		TOKEN = data.get('params').get('token')

		query_args = {
		"method":"log.getCount",
			"params": {
					"token": TOKEN,
				},
			"object":OBJECT,
			"session": self.SessionID,
			"id": self.ID
		}
		data = self.SendCall(query_args)
		if not data or not data.get('result'):
			log.failure('{} Failed'.format(query_args.get('method')))
			return False

#		COUNT = data.get('params').get('count')

		query_args = {
		"method":"log.doSeekFind",
			"params": {
					"token": TOKEN,
					"offset":0,
					"count":COUNT,
				},
			"object":OBJECT,
			"session": self.SessionID,
			"id": self.ID
		}
		data = self.SendCall(query_args)
		if not data.get('result'):
			log.failure('{} Failed'.format(query_args.get('method')))
			return False

		dlogs = data.get('params').get('items')
		found = data.get('params').get('found')

		log.info('Found: {}'.format(found))

		for dlog in dlogs:
			print('{}Detail: {}\nUser: {}, Device: {}, Type: {}, Level: {}'.format(
				helpMsg(dlog.get('Time')),
				dlog.get('Detail'),
				dlog.get('User'),
				dlog.get('Device'),
				dlog.get('Type'),
				dlog.get('Level'),
				))

		query_args = {
		"method":"log.stopFind",
			"params": {
					"token": TOKEN,
				},
			"object":OBJECT,
			"session": self.SessionID,
			"id": self.ID
		}
		data = self.SendCall(query_args)
		if not data.get('result'):
			log.failure('{} Failed'.format(query_args.get('method')))

		self.InstanceService(methodName,stop=True)

		return

	def TEST(self,msg):

		log.success('Test: {}'.format('Anonymous' if args.test else 'Authenticated'))

		return

#############################################################################################################
#
# Utility functions
#
#############################################################################################################

class Utility:

	def __init__(self):
		self.check = ''

	# Check if IP is valid
	def CheckIP(self,ipAddr):

		try:
			ip = ipAddr.split('.')
			if len(ip) != 4:
				return False
			for tmp in ip:
				if not tmp.isdigit():
					return False
				i = int(tmp)
				if i < 0 or i > 255:
					return False
			return True
		except ValueError as e:
			return False

	# Check if PORT is valid
	def Port(self,port):
		try:
			if not isinstance(port,int):
				port = int(port)
			if int(port) < 1 or int(port) > 65535:
				return False
			else:
				return True
		except ValueError as e:
			return False

	# Check if HOST is valid
	def Host(self,ipAddr):

		try:
			# Check valid IP
			socket.inet_aton(ipAddr) # Will generate exeption if we try with DNS or invalid IP
			# Now we check if it is correct typed IP
			if self.CheckIP(ipAddr):
				return ipAddr
			else:
				return False
		except socket.error as e:
			# Else check valid DNS name, and use the IP address
			try:
				return(socket.gethostbyname(ipAddr))
			except socket.error as e:
				return False

	# Modified pwntools function from "misc.py"
	def binary_ip(self,host, endian="big"):
		"""
		big: 127.0.0.1 => b'\\x7f\\x00\\x00\\x01'
		little: 127.0.0.1 => b'\\x01\\x00\\x00\\x7f'
		"""
		try:
			# Swap endianness if desired
			return p32(u32(socket.inet_aton(socket.gethostbyname(host)),endian="big" if endian == "little" else "little"))
		except (Exception, KeyboardInterrupt, SystemExit) as e:
			return str(e)

	def unbinary_ip(self,host,endian="big"):
		"""
		big: b'\\x7f\\x00\\x00\\x01' => 127.0.0.1
		little: b'\\x01\\x00\\x00\\x7f' => 127.0.0.1
		"""
		try:
			# Swap endianness if desired
			host = p32(u32(host,endian="big" if endian == "little" else "little"))
			return '.'.join(str(x) for x in [u8(host[i:i+1]) for i in range(0,len(host), 1)])
		except (Exception, KeyboardInterrupt, SystemExit) as e:
			return str(e)



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

#	def __del__(self):
#
#		log.success(color('Successful instance termination of _baseDes',GREEN))

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

#############################################################################################################
#
# main() function
#
#############################################################################################################

if __name__ == '__main__':

#
# Help, info and pre-defined values
#	
	INFO =  '[Dahua JSON Debug Console 2019-2021 bashis <mcw noemail eu>]\n'
	RHOST = '192.168.57.20'			# Default Remote HOST
	RPORT = 37777					# Default Remote PORT (Normally DVRIP used port)
#	RPORT = 5000					# Default Remote PORT (Normally DHIP used port)
#	RPORT = 80						# Default Remote PORT (PoC that normal HTTP port working too with DHIP/DVRIP)
#	CREDS = 'admin:admin'			# Default
#	CREDS = 'anonymity:anonymity'	# Anonymous Login must be enabled for this account
	PROTO = 'dvrip' 				# Protocol: dhip, dvrip, 3des

#
# Try to parse all arguments
# 
	try:
		arg_parser = argparse.ArgumentParser(
		prog=sys.argv[0],
				description=('[*] '+ INFO +' [*]'))
#		arg_parser.add_argument('--lhost', required=False, default=RHOST, help='Local Address (IP/FQDN) [Default: '+ RHOST +']')
#		arg_parser.add_argument('--lport', required=False, type=int, help='Local Port [Default: '+ str(RPORT) +']')
		arg_parser.add_argument('--rhost', required=False, default=RHOST, help='Remote Target Address (IP/FQDN) [Default: '+ RHOST +']')
		arg_parser.add_argument('--rport', required=False, type=int, help='Remote Target HTTP/HTTPS Port [Default: '+ str(RPORT) +']')
		arg_parser.add_argument('--proto', required=False, type=str, choices=['dhip', 'dvrip', '3des'],default=PROTO, help='Protocol [Default: '+ PROTO +']')
		arg_parser.add_argument('--auth', required=False, type=str, default=None, help='Basic Authentication [Default: None]')
		arg_parser.add_argument('--ssl', required=False, default=False, action='store_true', help='Use SSL for remote connection [Default: False]')
		arg_parser.add_argument('-d','--debug', required=False, default=0, const=0x1, dest="debug", action='store_const', help='Debug (normal)')
		arg_parser.add_argument('-dd','--ddebug', required=False, default=0, const=0x2, dest="ddebug", action='store_const', help='Debug (hexdump)')
		arg_parser.add_argument('--dump', required=False, default=False, type=str, choices=['config', 'service','device','discover','log','test'], help='Dump remote config')
		arg_parser.add_argument('--dump_argv', required=False, default=None, type=str, help='ARGV to --dump')
		arg_parser.add_argument('--test', required=False, default=False, action='store_true', help='test w/o login')
		arg_parser.add_argument('--multihost', required=False, default=False, action='store_true', help='Connect hosts from "dhConsole.json"')
		arg_parser.add_argument('--save', required=False, default=False, action='store_true', help='Save host hash to "dhConsole.json"')
		arg_parser.add_argument('--events', required=False, default=False, action='store_true', help='Subscribe to events [Default: True]')
		arg_parser.add_argument('--eventviewer', required=False, default=False, action='store_true', help='Connect localhost to view events')
		arg_parser.add_argument('--discover', required=False, type=str, choices=['dhip', 'dvrip'], help='Discover local devices')
		arg_parser.add_argument('-f','--force', required=False, default=False, action='store_true', help='Set this to bypass stops for dangerous commands')
		args = arg_parser.parse_args()
	except Exception as e:
		print(INFO,"\nError: {}\n".format(str(e)))
		sys.exit(False)

	# We want at least one argument, so print out help
	if len(sys.argv) == 1:
		arg_parser.parse_args(['-h'])

	log.info(INFO)
	status = True

	args.debug = args.debug + args.ddebug

	if (args.proto == 'dvrip' or args.proto == '3des') and not args.rport:
		args.rport = 37777
	elif args.proto == 'dhip' and not args.rport:
		args.rport = 5000

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

	#
	# just to do the opposite from args.events
	# (Want to have them enabled by default, but be able to disable if we add the --events switch)
	#
	args.events = True if not args.events else False

	util = Utility()
	# Check if RPORT is valid
	if not util.Port(args.rport):
		log.failure("Invalid RPORT - Choose between 1 and 65535")
		status = False

	# Check if RHOST is valid IP or FQDN, get IP back
	args.rhost = util.Host(args.rhost)
	if not args.rhost:
		log.failure("Invalid RHOST")
		status = False

#
# Validation done, start print out stuff to the user
#

	if args.eventviewer:
		try:
			status = SimpleEventViewer()
			status = False
		except (PwnlibException, Exception, KeyboardInterrupt, SystemExit) as e:
			status = False

	if status:
		if args.ssl:
			log.info("SSL Mode Selected")
		if args.discover:
			if args.rhost == RHOST:
				if args.discover == 'dhip':
					args.rhost = '239.255.255.251' # Multicast
				elif args.discover == 'dvrip':
					args.rhost = '255.255.255.255' # Broadcast
			DH = Dahua_Functions()
			DH.DHDiscover("ldiscover {} {}".format(args.discover, args.rhost))
		else:
#			try:
			status = DebugConsole()
#			except Exception as e:
#				pass

	log.info("All done")

