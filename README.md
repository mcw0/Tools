# Tools
Some tools (feedback / bug reports are appreciated)

Dahua-JSON-Debug-Console-v2.py
---

2021-03-02

Misc bug fixes and tuning for performance of self.P2P()

DHIP artifact: Removed ["magic":"0x1234"]

2021-02-08

Fixed some bugs

2021-01-23

Major rewrite:
1.	Implemented 'multicall' - big timesaver (!) (not 100% consistent usage for now, but working good as it is)
2.	'SendCall()' wrapper around 'self.P2P()'. self.P2P() should not be used directly (unless you want raw data).
3.	'console' Multiple simultaneous connections to devices, easy switching between active Console
4.	'password manager', create/change Dahua hash and connection details for devices, saved in 'dhConsole.json'
	- No fancy own encryption/decryption, we simply use the Dahua 'one way' format to save and pass on hashes.
	- ./Dahua-JSON-Debug-Console-v2.py --rhost \<RHOST\> --proto \<PROTO\> --rport \<RPORT\> --auth \<USERNAME\>:\<PASSWORD\> --save
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

2020-02-29

- Added option 'setDebug', Should start produce output from Debug Console in VTO/VTH
- Added '--discover', Multicast search of devices or direct probe (--rhost 192.168.57.20) of device via UDP/37810
- Added '--dump {config,service}' for dumping config or services on remote host w/o entering Debug Console

2020-01-20

- Ported to Python 3
- Fixed some bugs and code adjustment
- Added support for DVRIP (TCP/37777) [Note: Some JSON commands that working with DHIP return nothing with DVRIP]
- encode/decode in latin-1, we might need untouched chars between 0x00 - 0xff
- Better 'debug' with hexdump as option

https://github.com/mcw0/Tools/blob/master/Dahua-JSON-Debug-Console-v2.py
