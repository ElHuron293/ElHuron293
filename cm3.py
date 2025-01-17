#!/usr/bin/python3
# -*- coding: utf-8 -*-


"""
This is a simple script that encrypts and decrypts files in AES256.
It uses PBKDF2 to create a key from a password and a salt.
It is build on top of the python3 (standard) cryptography library.
"""


import os
import sys
from random import randint as rd
from getpass import getpass
from hashlib import pbkdf2_hmac

# -- importing the crypto modules --
from cryptography.hazmat.primitives.ciphers import (
	Cipher, algorithms, modes
)
from cryptography.hazmat.backends import default_backend



""" --- global variables
"""
argsc = sys.argv[1:]
bsize = 1048576  # -> byte size must be a multiple of 16 (i.e. 32, 64, ..., 1048576)
hsize = 64


""" --- parse command arguments from command line
"""
lst_argvc = []  # -> list of commands

i = 0
for c in argsc:
	if c[0] == "-":
		if len(argsc[i]) > 2:
			for e in argsc[i][1:]:
				lst_argvc.append(e)
		else:
			lst_argvc.append(argsc[i][1:])
	i += 1


""" --- show commands and exit if no argument was given
"""
if len(argsc) == 0:
	print("\n"
		"Commands:\n---------\n"
		"  -i:  infos of program\n"
		"  -e:  encrypt files\n"
		"  -d:  decrypt files\n"
		"  -c:  delete original file\n"
		"  -s:  overwrite and delete original file\n"
		"  -v:  verbose actions\n"
		"  -p:  password on the command line (unsafe)\n"
	)
	sys.exit(0)


def INFO():
	print("\n"
		"Informations of cm3:\n"
		"--------------------\n"
		"Encryption mode:   AES256-CBC + IV\n"
		"How to run:        cm3 <command(s)> <file(s)>\n"
	)
	sys.exit(0)


def _get_files():
	""" check if selected files exist and return them
	"""
	lst_files = []
	for f in argsc:
		if os.path.isfile(f) is True:
			lst_files.append(f)
	if len(lst_files) > 0:
		return lst_files
	else:
		sys.exit("File(s) not found - non selected!!!")


def _get_fname(path_fname):
	""" extract filename from path
	"""
	f_name = path_fname.split("/")[-1]
	return f_name


def _get_password():
	""" get password for encryption and decryption
	"""
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
		if "e" in lst_argvc:
			fpwd1 = getpass(prompt="Enter password: ")
			fpwd2 = getpass(prompt="Verify password: ")
			if fpwd1 == fpwd2:
				fpassword = fpwd1
			else:
				sys.exit("Password verification failed!!!")
		else:
			fpassword = getpass(prompt="Enter password: ")

	# return encoded password -> must be ASCII encoded for hashing
	try:
		return fpassword.encode("ascii")
	except UnicodeEncodeError:
		sys.exit("Invalid password!!! ASCII characters only!!!")


def _get_progress(_i, _fsize, _mode=None):
	""" show progress in percent
	"""
	if "v" in lst_argvc:
		print("Progress: " + str(round(_i / _fsize * 100)) + "%", end="\r")


def _get_salt(rsize=16):
	""" generate a unique salt for each file for the key (16^16)
	"""
	charset = "0123456789abcdef"
	fsalt = ""
	for n in range(rsize):
		fsalt += charset[rd(0,15)]

	return fsalt.encode("ascii")


def _get_key(_password, _salt, _iter=390000):
	""" generate key from password and salt -> using PBKDF2
	"""
	dk = pbkdf2_hmac("sha512", _password, _salt, _iter)
	key = dk[0:32]  # 32-byte key = 256-bit for AES256
	iv = dk[32:48]  # 16-byte iv = 128-bit for an AES-block
	sk = dk[48:64]  # 16-byte signing key (error handling and verification)
	return (key, iv, sk)


def sizes(fname1):
	""" some size calculations of files
	"""
	fsize = os.path.getsize(fname1)
	rbytes = fsize % bsize % 16  # -> remaining bytes for a 128-bit block
	return (fsize, rbytes)


def randbytes(xsize):
	""" generate some random bytes from ASCII (extended) hex digests
	"""
	hstring = ""
	for n in range(xsize):
		hdigest = hex(rd(0,255))[2:]
		if len(hdigest) == 1:
			hstring += '0' + hdigest
		else:
			hstring += hdigest

	return bytes.fromhex(hstring)


def encryption(key, iv, plaintext):
	""" encrypt the plaintext from chunks
	"""
	cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
	encryptor = cipher.encryptor()
	enctxt = encryptor.update(plaintext) + encryptor.finalize()
	return enctxt


def encryptf(fname, password):
	""" encryption of file
	"""
	with open(fname + ".cr", "wb") as f_out:
		with open(fname, "rb") as f_in:

			salt = _get_salt()
			key_args = _get_key(password, salt)
			key = key_args[0]
			iv = key_args[1]
			sk = key_args[2]

			fsize_c = sizes(fname)[0]			# size of file
			rbytes_c = 16 - sizes(fname)[1]		# size of remaining bytes
			sbytes_c = str(rbytes_c)			# convert to string for writing

			# 'sbytes_c' must have a length of 2 bytes (00 - 16)
			if len(sbytes_c) < 2: sbytes_c = '0' + sbytes_c

			# this is the encrypted signing block to verify the key
			esk = encryption(key, iv, sk)

			# write a byte-header with information at beginning of file
			hdata = b"s=" + salt + b"\0b=" + sbytes_c.encode("ascii") + b"\0" + esk
			header = hdata + ((hsize - len(hdata)) * b"\0")
			f_out.write(header)

			# read files in chunks, encrypt and write to outfile
			i = 0
			while True:
				chunks = f_in.read(bsize)
				if not chunks:
					break
				if i > (fsize_c - bsize):  # -> padding last chunk
					chunks = chunks + randbytes(rbytes_c)
				enc = encryption(key, iv, chunks)
				f_out.write(enc)

				# get the progress of encryption
				_get_progress(i, fsize_c)

				i += len(chunks)

	# run some additional commands
	fadds(fname, fname + ".cr", fsize_c)


def decryption(key, iv, chipertext):
	""" decrypt the ciphertext from chunks
	"""
	cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
	decryptor = cipher.decryptor()
	dectxt = decryptor.update(chipertext) + decryptor.finalize()
	return dectxt


def decryptf(fname, password):
	""" decryption of file
	"""
	# at first check filename for '*.cr' ending
	if fname[-3:] != ".cr":
		print("%s: Non-encryption file for cm3!!!\n-> Type: <path/file>.cr" %_get_fname(fname))
		return -1

	with open(fname[:-3], "wb") as f_out:
		with open(fname, "rb") as f_in:

			header = f_in.read(hsize)
			salt = header[2:18]		# salt from header
			pad = header[21:23]		# bytes to remove when decryption was done
			esk = header[24:40]		# encrypted signing key

			# get size of file without the header
			fsize_c = sizes(fname)[0] - hsize

			key_args = _get_key(password, salt)
			key = key_args[0]
			iv = key_args[1]
			sk = key_args[2]

			# verfiy decryption key -> return with error if it fails
			sdk = decryption(key, iv, esk)
			if sdk.hex() != sk.hex():
				print("KeyError: Decryption key for '%s' did not work!!!" %_get_fname(fname))
				os.remove(fname[:-3])
				return -1

			# read file in chunks, decrypt and write to outfile
			i = 0
			while True:
				chunks = f_in.read(bsize)
				if not chunks:
					break
				dec = decryption(key, iv, chunks)
				f_out.write(dec)

				# get the progress of decryption
				_get_progress(i, fsize_c)

				i += len(chunks)

			# delete the 'padded' random bytes from file
			tsize = fsize_c - int(pad.decode("ascii"))
			f_out.truncate(tsize)

	# run some additional commands
	fadds(fname, fname[:-3], fsize_c)


def fadds(*args):
	""" several additional actions
		(arg01: infile, arg02: outfile, arg03: filesize)
	"""
	# verbose actions
	if "v" in lst_argvc:
		print("'%s' -> '%s'" %(args[0], args[1]))

	# overwrite and/or remove file
	if "s" in lst_argvc:
		rmkfile(args[0], args[2])
	elif "c" in lst_argvc:
		rmkfile(args[0], args[2], 1)


def rmkfile(file_x, size_x, f=0):
	""" overwrite (kill) and/or remove file
	"""
	if f == 0:  # -> flag for overwriting and removing
		if "v" in lst_argvc:
			print("Start to overwrite...", end="\r")

		# create 1MB ASCII encoded chunk of '0' for overwrite
		mbchunk = ("0" * 1048576).encode("ascii")

		# open file and overwrite it with MB-chunks
		with open(file_x, "r+b") as f_kill:
			i = 0
			while True:
				if i < size_x:
					f_kill.write(mbchunk)
				else:
					break
				i += len(mbchunk)

		# finally remove overwriten file
		os.remove(file_x)
		if "v" in lst_argvc:
			print("File '%s' overwriten and removed." %file_x)

	if f == 1:  # -> flag for removing only
		os.remove(file_x)
		if "v" in lst_argvc:
			print("File '%s' removed." %file_x)



def main():

	if argsc[0] == "-i":
		INFO()

	if len([n for n in lst_argvc if n in ["e", "d"]]) == 0:
		sys.exit("Missing commands [ -e | -d ] !!!")

	if "e" in lst_argvc and "d" in lst_argvc:
		sys.exit("Only encryption (-e) or decryption (-d) at the same time possible!!!")
	else:
		lst_files = _get_files()	# -> get files
		password = _get_password()	# -> get password
		for f in lst_files:
			if "e" in lst_argvc:
				encryptf(f, password)
			elif "d" in lst_argvc:
				decryptf(f, password)


if __name__ == "__main__":
	main()


