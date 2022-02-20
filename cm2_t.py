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


# -- help function: show available commands of program --
def _help():
	pcommands = """
Commands:
  -e:  encrypt files
  -d:  decrypt files
  -r:  delete original file
  -v:  verbose actions
  -p:  password on the command line
	"""
	sys.exit(pcommands)


# -- parse command arguments from command line --
def _argp():
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


# -- check, if selected files exist and return them --
def _get_files():
	lst_files = []
	for f in argsc:
		if os.path.isfile(f) == True:
			lst_files.append(f)
	if len(lst_files) > 0:
		return lst_files
	else:
		sys.exit("File(s) not found - non selected!!!")


# -- get password for encryption and decryption --
def _get_password():
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

	return fpassword


#  -- generate a unique salt for each file for the key --
def _get_salt(_size=16):

	f_salt = "".join([str(randint(0,9)) for n in range(_size)])
	return f_salt


# -- generate key from password --
def _get_key(_pw, _slt, _length=32, _iter=390000):
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


# -- generator to read file in chunks --
def _read_chunks_generator(file_object, chunksize=1048576):
	" function needs the file object "
	# 1 KB chunks:  1024     -> 1 KB
	# 1 MB chunks:  1048576  -> 1 MB (default)
	# ...           ...         ...

	while True:
		fdata = file_object.read(chunksize)
		if not fdata:
			break
		yield fdata


# -- encryption of file --
def encryptf(_file_, pwenc):

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
	for c in _read_chunks_generator(fcontent):
		fcenc = ft.encrypt(c)
		open(_file_ + ".cr", "ab").write(fcenc)
		open(_file_ + ".cr", "a").write("\n")

	_adds(_file_, _file_ + ".cr")


# -- decryption of file --
def decryptf(_file_, pwdec):

	if _file_[-3:] != ".cr":
		sys.exit("Non-encryption file for cm2!!!\n-> Type: <path/file>.cr")

	# re-build original filename and open new file
	nFileName = _file_[:-3]
	rFile = open(nFileName, "wb")

	# re-create the key by using password prompt and salt from file
	salt = open(_file_, "r").read(16)
	fkey = _get_key(pwdec, salt)
	ft = Fernet(fkey)

	# -- function for file decryption -> using temporary file --
	def _chunks_decryption():

		with open(_file_, "r") as fcontent:

			i = 1
			for r in fcontent:
				tmp_file = open(_file_ + ".tmp", "w")

				if i == 1:
					tmp_file.write(r[16:][:-1])
				else:
					tmp_file.write(r[:-1])
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


# -- several additional actions --
def _adds(*args):
	# 0 -> arg1: read filename
	# 1 -> arg2: new filename

	# verbose actions
	if "-v" in _argp():
		print("'" + args[0] + "' -> '" + args[1] + "'")

	# remove '_file_'
	if "-r" in _argp():
		os.remove(args[0])



# -- main function of program --
def mainf():

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



