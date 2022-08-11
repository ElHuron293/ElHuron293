#!/usr/bin/python3
# -*- coding: utf-8 -*-


"""
This is a simple script that encrypts and decrypts files in AES128.
It uses PBKDF2 to create a key from a password and a salt.
It is build on top of the Python3 cryptography library.
"""


import sys
import os
import base64
from random import randint
from getpass import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend



""" --- global variables
"""
argsc = sys.argv[1:]	# command line arguments
mbsize = 1048576		# size of 1 MB (2^20)


""" --- parse command arguments from command line
"""
# '-' will be used to define a command on the cli
# arguments that follow '-' will be parsed if > 1
# the list contains all commands from the cli

lst_argvc = []  # -> list of commands

i = 0
for c in argsc:
	if c[0] == "-":
		if len(argsc[i]) > 2:
			for e in argsc[i][1:]:
				lst_argvc.append(f"-{e}")
		else:
			lst_argvc.append(argsc[i])
	i += 1


""" --- show commands/informations of cm2
"""
try:
	if lst_argvc[0] == "-h":
		print("\n"
			"Commands:\n---------\n"
			"  -e:  encrypt files\n"
			"  -d:  decrypt files\n"
			"  -r:  overwrite and delete original file\n"
			"  -v:  verbose actions\n"
			"  -p:  password on the command line (unsafe)\n"
		)
		sys.exit(0)
except IndexError:
	pass  # -> pass for further actions



def _get_files():
	""" check if selected files exist and return them """
	lst_files = []
	for f in argsc:
		if os.path.isfile(f) is True:
			lst_files.append(f)
	if len(lst_files) > 0:
		return lst_files
	else:
		sys.exit("File(s) not found - non selected!!!")


def _get_password():
	""" get password for encryption and decryption """
	fpassword = None

	i = 0
	for n in argsc:
		if n == "-p":
			try:
				fpassword = argsc[i+1]
				print("Note: Passwords on the command line are unsafe as they log!!!")
			except IndexError:
				sys.exit("Password is missing!!!")
			break
		i += 1

	if fpassword is None:
		if "-e" in lst_argvc:
			fpwd1 = getpass(prompt="Enter password: ")
			fpwd2 = getpass(prompt="Verify password: ")
			if fpwd1 == fpwd2:
				fpassword = fpwd1
			else:
				sys.exit("Password verification failed!!!")
		else:
			fpassword = getpass(prompt="Enter password: ")

	# check password for invalid ascii-encoding-characters
	try:
		password_test_encode = fpassword.encode("ascii")
	except UnicodeEncodeError:
		sys.exit("Invalid password!!! ASCII characters only!!!")

	return fpassword


def _get_progress(_i, _fsize, _m):
	""" show progress in percent """

	if _m == "_e":
		progress = _i * mbsize / _fsize
	if _m == "_d":
		progress = _i / _fsize

	if "-v" in lst_argvc:
		print(f"Progress: {round(progress * 100)}%", end="\r")


def _get_salt(_size=16):
	""" generate a unique salt for each file for the key """
	f_salt = "".join([str(randint(0,9)) for n in range(_size)])
	return f_salt


def _get_key(_pw, _slt, _length=32, _iter=390000):
	""" generate key from password and salt -> using PBKDF2 """
	# _pw:      argument takes the password
	# _slt:     salt (as string) for the key
	# _length:  the length for the encryption key
	# _iter:    iterations of PBKDF2 (iteration count)

	# *** password and salt will be encoded as binary ***

	_password = _pw.encode("ascii")
	_salt = _slt.encode("ascii")

	_kdf = PBKDF2HMAC(
		algorithm=hashes.SHA256(),
		length=_length,
		salt=_salt,
		iterations=_iter,
		backend=default_backend()
	)

	_fkey = base64.urlsafe_b64encode(_kdf.derive(_password))
	return _fkey


def encryptf(_file_, pwenc):
	""" encryption of file """

	# create new file for encryption content
	f_out = open(f"{_file_}.cr", "w")

	# get salt for the encryption key and write it to file
	salt = _get_salt()
	f_out.write(salt)

	# create the key by using password and salt
	fkey = _get_key(pwenc, salt)
	ft = Fernet(fkey)

	# open file that contains content to encrypt and get size
	f_in = open(_file_, "rb")
	fsize = os.path.getsize(_file_)

	# encrypt file content in chunks (1 MB at the time)
	i = 1
	while True:
		chunks = f_in.read(mbsize)
		if not chunks:
			break

		fcenc = ft.encrypt(chunks)
		fcadc = fcenc.decode("ascii")
		f_out.write(f"{fcadc}\n")

		_get_progress(i, fsize, "_e")

		i += 1

	# close in- and out-file
	f_in.close()
	f_out.close()

	_adds(_file_, f"{_file_}.cr", fsize)


def decryptf(_file_, pwdec):
	""" decryption of file """

	if _file_[-3:] != ".cr":
		print(f"{_file_}: Non-encryption file for cm2!!!\n-> Type: <path/file>.cr")
		return -1

	# re-build original filename and open new file
	fname = _file_[:-3]
	f_out = open(fname, "wb")

	# open encrypted file and get size
	f_in = open(_file_, "r")
	fsize = os.path.getsize(_file_)

	# get salt from file and re-create key by using password prompt
	try:
		salt = f_in.read(16)
	except UnicodeDecodeError:  # -> check if it might be a manipulated '*.cr' file
		os.remove(fname) ; f_in.close()
		print(f"Cannot decode '{_file_}'!!!\n-> File might be manipulated.")
		return -1
	fkey = _get_key(pwdec, salt)
	ft = Fernet(fkey)

	# iterate and decrypt line by line from encrypted file
	i = 1
	for r in f_in:
		xc = r[:-1]
		xcdec = xc.encode("ascii")
		try:
			fcdec = ft.decrypt(xcdec)
		except:
			os.remove(fname) ; f_in.close()
			print(f"Wrong password for '{_file_}'. Try again!!!")
			return -1
		f_out.write(fcdec)

		_get_progress(len(xc)*i, fsize, "_d")

		i += 1

	# close in- and out-file
	f_in.close()
	f_out.close()

	_adds(_file_, fname, fsize)


def _adds(*args):
	""" several additional actions """
	# 0 -> arg1: read filename
	# 1 -> arg2: new filename
	# 2 -> arg3: size of file

	# verbose actions
	if "-v" in lst_argvc:
		print(f"'{args[0]}' -> '{args[1]}'")

	# overwrite/remove file
	if "-r" in lst_argvc:
		_killrm_file(args[0], args[2])


def _killrm_file(file_f, size_f, f=0):
	""" overwrite (kill) and remove file """

	if f == 0:  # f: flag -> 0 = overwrite and remove
		if "-v" in lst_argvc:
			print("Start to overwrite...", end="\r")

		# create 1 MB ascii-encoded chunk of NUL for overwrite
		mbchunk = ('\x00' * mbsize).encode("ascii")

		# open file and overwrite it with MB-chunks
		f_kill = open(file_f, "r+b")

		i = 0
		while True:
			if i < size_f:
				f_kill.write(mbchunk)
			else:
				break
			i = i + mbsize

		# finally close file and remove it
		f_kill.close()
		os.remove(file_f)

		if "-v" in lst_argvc:
			print(f"File '{file_f}' overwriten and removed.")

	elif f == 1:  # f: flag -> 1 = remove only
		os.remove(file_f)



def main():

	# if no argument on the cli was given, show options
	if len(argsc) < 1:
		sys.exit("Missing arguments!!!\n'cm2 -h' will show further informations.")

	if len([n for n in lst_argvc if n in ["-e", "-d"]]) == 0:
		sys.exit("Missing commands [ -e | -d ] !!!")

	if "-e" in lst_argvc and "-d" in lst_argvc:
		sys.exit("Only encryption (-e) or decryption (-d) at the same time possible!!!")
	else:
		lst_files = _get_files()	# -> get files
		password = _get_password()	# -> get password
		for f in lst_files:
			if "-e" in lst_argvc:
				encryptf(f, password)
			elif "-d" in lst_argvc:
				decryptf(f, password)


if __name__ == "__main__":
	main()



