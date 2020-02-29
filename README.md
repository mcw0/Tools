# Tools
Some tools (feedback / bug reports are appreciated)

Dahua-JSON-Debug-Console-v2.py
---
2020-02-29

Added option 'setDebug', Should start produce output from Console in VTO/VTH

2020-01-20

- Ported to Python 3
- Fixed some bugs and code adjustment
- Added support for DVRIP (TCP/37777) [Note: Some JSON commands that working with DHIP return nothing with DVRIP]
- encode/decode in latin-1, we might need untouched chars between 0x00 - 0xff
- Better 'debug' with hexdump as option

https://github.com/mcw0/Tools/blob/master/Dahua-JSON-Debug-Console-v2.py
