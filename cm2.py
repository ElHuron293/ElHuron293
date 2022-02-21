#!/usr/bin/python3


"""
This is as simple encryption program that encrypts files in AES128.
It uses PBKDF2 to create a key from a password and a salt.
It uses the Python3 cryptography library which should be installed by default.
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


argsc = sys.argv[1:]	# command line arguments



def _help():
	# available commands of program ('-h' will show them)
	pcommands = """
Commands:
  -e:  encrypt files
  -d:  decrypt files
  -r:  delete original file
  -v:  verbose actions
  -p:  password on the command line (unsafe)
	"""
	sys.exit(pcommands)


def _argp():
	""" parse command arguments from command line """
	# '-' will be used to define a command on the cli
	# args that follow '-' will be parsed if > 1
	# the function will return a list of all commands

	lst_argsc = []
	i = 0
	for c in argsc:
		if c[0] == "-":
			if len(argsc[i]) > 2:
				for e in argsc[i][1:]:
					lst_argsc.append("-"+e)
			else:
				lst_argsc.append(argsc[i])
		i += 1

	return lst_argsc


def _get_files():
	""" check, if selected files exist and return them """
	lst_files = []
	for f in argsc:
		if os.path.isfile(f) == True:
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
				print("Notice: Passwords on the command line are unsafe as they log!!!")
			except IndexError:
				sys.exit("Password is missing!!!")
		i += 1

	if fpassword == None:
		fpassword = getpass(prompt="Enter password: ")

	# check password for invalid ascii-encoding-characters
	lst_invalid_charset = ["ö", "ä", "ü", "ß", "§"]
	if len([n for n in fpassword if n in lst_invalid_charset]) > 0:
		sys.exit("Invalid password!!! No special characters allowed!!!")

	return fpassword


def _get_progress(_i, _fsize, _m):
	""" show progress in percent """

	if _m == "_e":
		progress = _i * 1048576 / _fsize
	if _m == "_d":
		progress = _i / _fsize

	progperc = round(progress * 100)

	if "-v" in _argp():
		print("Progress: " + str(progperc) + "%", end="\r")


def _get_salt(_size=16):
	""" generate a unique salt for each file for the key """
	f_salt = "".join([str(randint(0,9)) for n in range(_size)])
	return f_salt


def _get_key(_pw, _slt, _length=32, _iter=390000):
	""" generate key from password and salt -> using PBKDF2 """
	# _pw:      argument takes the password
	# _slt:     salt (as string) for the key
	# _length:  the length for the encryption key
	# _iter:    iterations of PBKDF2 (round count)

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


def _read_chunks_generator(file_object, chunksize=1048576):
	""" the generator to read file in chunks """
	# 1 KB chunks:  1024     -> 1 KB
	# 1 MB chunks:  1048576  -> 1 MB (default)
	# ...           ...         ...

	while True:
		fdata = file_object.read(chunksize)
		if not fdata:
			break
		yield fdata


def encryptf(_file_, pwenc):
	""" encryption of file """

	# create new file for encryption
	nFile = open(_file_ + ".cr", "w")

	# get salt for the encryption key and write to file
	salt = _get_salt()
	nFile.write(salt)
	nFile.close()

	# create the key by using password and salt
	fkey = _get_key(pwenc, salt)
	ft = Fernet(fkey)

	# open file as binary object and run generator
	fcontent = open(_file_, "rb")
	i = 1
	for c in _read_chunks_generator(fcontent):
		fcenc = ft.encrypt(c)
		open(_file_ + ".cr", "ab").write(fcenc)
		open(_file_ + ".cr", "a").write("\n")

		_get_progress(i, os.path.getsize(_file_), "_e")

		i += 1

	_adds(_file_, _file_ + ".cr")


def decryptf(_file_, pwdec):
	""" decryption of file """

	if _file_[-3:] != ".cr":
		sys.exit("Non-encryption file for cm2!!!\n-> Type: <path/file>.cr")

	# re-build original filename and open new file
	nFileName = _file_[:-3]
	rFile = open(nFileName, "wb")

	# re-create key by using password prompt and get salt from file
	salt = open(_file_, "r").read(16)
	fkey = _get_key(pwdec, salt)
	ft = Fernet(fkey)

	def _chunks_decryption():
	""" function for file decryption -> using temporary file """

		with open(_file_, "r") as fcontent:

			i = 1
			for r in fcontent:
				tmp_file = open(_file_ + ".tmp", "w")

				if i == 1:
					tmp_file.write(r[16:][:-1])
				else:
					tmp_file.write(r[:-1])

				_get_progress(
					os.path.getsize(_file_ + ".tmp") * i,
					os.path.getsize(_file_),
					"_d"
				)  # -> factor = 1.398217 (size)

				tmp_file.close()

				# write decoding content to outfile
				xcdec = open(_file_ + ".tmp", "rb").read()
				try:
					fcdec = ft.decrypt(xcdec)
				except:
					os.system("rm " + _file_ + ".tmp " + nFileName)
					sys.exit("Wrong password, try again!!!")
				rFile.write(fcdec)
				tmp_file.close()

				i += 1

		# delete temporary file when decryption is done
		os.remove(_file_ + ".tmp")

	_chunks_decryption()

	_adds(_file_, nFileName)


def _adds(*args):
	""" several additional actions """
	# 0 -> arg1: read filename
	# 1 -> arg2: new filename

	# verbose actions
	if "-v" in _argp():
		print("'" + args[0] + "' -> '" + args[1] + "'")

	# remove '_file_'
	if "-r" in _argp():
		os.remove(args[0])



def mainf():
	"""
	This is the main function of the program.
	The main function runs the encryption and decryption.
	It also checks on cli arguments
	"""

	if len(_argp()) < 1:
		sys.exit("Missing arguments, Enter '-h' for help!!!")

	if _argp()[0] == "-h":
		_help()

	if len([n for n in _argp() if n in ["-e", "-d"]]) == 0:
		sys.exit("Wrong arguments!!!")

	lst_files = _get_files()
	password = _get_password()

	if "-e" in _argp() and "-d" in _argp():
		sys.exit("only encryption (-e) or decryption (-d) at the same time possible!!!")
	else:
		for f in lst_files:
			if "-e" in _argp():
				encryptf(f, password)
			elif "-d" in _argp():
				decryptf(f, password)


if __name__ == "__main__":
	mainf()



