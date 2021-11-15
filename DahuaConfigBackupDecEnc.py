#!/usr/bin/env python3

import json
import argparse
from hashlib import md5
from Crypto.Cipher import AES
from struct import pack, unpack

"""
Author: bashis <mcw noemail eu> (2021) 
Tested: IPC/VTO/SD

-[Get _possible_ key with 'DahuaConsole' (https://github.com/mcw0/DahuaConsole)]-

Note: As usual with Dahua (sigh), their rules has always exceptions, and with my "SD" the key is simply "SD"

[Console]# uboot getenv HWID
{
    "id": 14,
    "params": {
        "table": {
            "HWID": "IPC-G42P-IMOU:01:02:03:04:05:06:07:08:09:10:11:123:00:00:00:00:00:00:00:00:000"
        }
    },
    "result": true,
    "session": 1178419111
}
[Console]# 

-[Demo]-

$ ./DahuaConfigBackupDecEnc.py --infile configFileExport.backup --key IPC-G42P-IMOU
[*] Dahua Config Backup Decrypt/Encrypt by bashis <mcw noemail eu> (2021) [*]

Decrypt "configFileExport.backup", key: IPC-G42P-IMOU
Version: 1
Config size   : 73356
Provided MD5  : B218592EA84B55319A40C064D91FD6C2
Calculated MD5: B218592EA84B55319A40C064D91FD6C2
Saved decrypted "configFileExport.backup.dec" (73356 bytes)

$ ./DahuaConfigBackupDecEnc.py --infile configFileExport.backup.dec --key IPC-G42P-IMOU
[*] Dahua Config Backup Decrypt/Encrypt by bashis <mcw noemail eu> (2021) [*]

Encrypt "configFileExport.backup.dec", key: IPC-G42P-IMOU
Version: 1
Config size   : 73356
Calculated MD5: B218592EA84B55319A40C064D91FD6C2
Saved encrypted "configFileExport.backup.enc" (73417)
"""


class AESCipher:
    def __init__(self, key):
        self.key = key.encode('utf8')

    def pad_zero(self, dh_data):
        dh_data += bytes(AES.block_size - (len(dh_data) % AES.block_size))
        return dh_data

    def ecb_encrypt(self, raw):
        cipher = AES.new(key=self.key, mode=AES.MODE_ECB)
        return cipher.encrypt(raw)

    def ecb_decrypt(self, raw):
        cipher = AES.new(key=self.key, mode=AES.MODE_ECB)
        return cipher.decrypt(raw)


def read_file(dh_name, dh_size=0):
    try:
        with open(dh_name, 'rb') as fd:
            if dh_size:
                return fd.read(dh_size)
            return fd.read()
    except IOError as e:
        print(f'[read_file] error ({e})')
        return None


def write_file(dh_name, dh_data):
    try:
        with open(dh_name, 'wb') as fd:
            return fd.write(dh_data)
    except IOError as e:
        print(f'[write_file] error ({e})')
        return None


def generate_backup_key(clear_text, dh_char_string):
    dh_string = "yaojinfucrang,yixitgchuanfei.vhuanglaiwaerqingfemgsheng,qiangeningerbaiyune.tuiyuanlvzbu," \
                "qilingxengzezhizfn;yeshuilhuhua,guakgzhaolinqhuanzhibi.zimeiju,ebnanbing."
    key = clear_text.encode('UTF-8')
    key += b'\x00' * 16

    key = md5(key).digest()
    """dh_char_string looks fixed to '1', assuming it means 1'st char in the 'dh_string'"""
    key += dh_string[dh_char_string].encode('UTF-8')
    key = md5(key).digest()

    key = md5(key).hexdigest()

    key = key[8:].encode('UTF-8')
    key += b'\x00' * (32 - (len(key) % 32))

    return key.decode('UTF-8')


def dh_backup(mode, file_name, key):
    offset = 9
    file = read_file(file_name)

    try:
        if mode == 'decrypt':
            """dh_char_string looks fixed to '1', assuming it means 1'st char in the 'dh_string'"""
            gen_key = generate_backup_key(key, dh_char_string=file[8] - 1)
            out = AESCipher(gen_key).ecb_decrypt(file[offset:])
            dh_size = unpack('i', out[1:5])[0]
            md5sum = out[dh_size + 5:].strip(b"\x00").decode('UTF-8')  # including 5 bytes header
            if not md5sum == md5(out[:dh_size + 5]).hexdigest().upper():
                print(f'[!] MD5 mismatch, decryption failed (correct key?)')
                return False
            if not file_name.rfind('.enc') == -1:
                file_name = file_name[:file_name.rfind('.enc')]
            written = write_file(file_name + '.dec', out[5:dh_size + 5])

            print(f'Version: {out[0]}')
            print(f'Config size   : {dh_size}')
            print(f'Provided MD5  : {md5sum}')
            print(f'Calculated MD5: {md5(out[:dh_size + 5]).hexdigest().upper()}')
            print(f'Saved decrypted "{file_name + ".dec"}" ({written} bytes)')
            return True
        elif mode == 'encrypt':
            version = 1
            dh_size = len(file)
            """dh_char_string looks fixed to '1', assuming it means 1'st char in the 'dh_string'"""
            gen_key = generate_backup_key(key, dh_char_string=version - 1)
            out = AESCipher(gen_key)
            config = pack('b', 1)
            config += pack('i', dh_size)
            config += file
            md5sum = md5(config).hexdigest().upper().encode('latin-1')
            config += md5sum
            config = out.pad_zero(config)
            out = out.ecb_encrypt(config)
            out = b'MWPZWJGS' + pack('b', version) + out
            if not file_name.rfind('.dec') == -1:
                file_name = file_name[:file_name.rfind('.dec')]
            written = write_file(file_name + '.enc', out)

            print(f'Version: {version}')
            print(f'Config size   : {dh_size}')
            md5sum = md5sum.decode('latin-1')
            print(f'Calculated MD5: {md5sum}')
            print(f'Saved encrypted "{file_name + ".enc"}" ({written})')
            return True
    except ValueError as e:
        print(f'Error: {e}')
        # TODO: NVR has base64 encodes backups, and seems not to share same key system for encryption/decryption
        return False


def main():

    print('[*] Dahua Config Backup Decrypt/Encrypt by bashis <mcw noemail eu> (2021) [*]\n')

    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--infile', metavar='\b', required=True, type=str, default=None, help='Encrypted or JSON unencrypted filename')
    parser.add_argument(
        '--key', metavar='\b', required=True, type=str, default=None, help='Encrypt/Decrypt key')
    args = parser.parse_args()

    file = read_file(args.infile, 25)
    if file is None:
        return False
    elif not len(file):
        print(f'[!] File "{args.infile}" is empty')
        return False

    #          bVar1 = std::operator==(param_4,"VTHRemoteIPCInfo");
    #          if (bVar1 == false) {
    #            pcVar11 = "MWPZWJGS";
    #          }
    #          else {
    #            pcVar11 = "DHRDENFR";
    #          }
    if file[0:8] == b'MWPZWJGS' or file[0:8] == b'DHRDENFR':
        print(f'Decrypt "{args.infile}", key: {args.key}')
        return dh_backup('decrypt', args.infile, args.key)
    else:
        try:
            json.loads(read_file(args.infile))
        except ValueError:
            print('[!] Input not valid JSON file')
            return False
        print(f'Encrypt "{args.infile}", key: {args.key}')
        return dh_backup('encrypt', args.infile, args.key)


if __name__ == '__main__':
    main()
