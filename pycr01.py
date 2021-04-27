#!/usr/bin/python3
# -*- coding utf-8 -*-

#run:	python3 ~/bin/pycr01.py

import sys, os
import shutil
from shutil import copyfile
import csv
import glob as gl
from cryptography.fernet import Fernet as ft
import re, hashlib as hlb
from getpass import getpass

#programm information
info="""
-- The program is used to encrypt almost all types of files created by an
   editor as well as csv-files.
-- At the beginning of the program a key and password will be created.
   To remove either of them type 'r' to command line.
   If no key is found, the system creates a new key at the beginning.
-- Notice: removing the key disables the decryption of all encrypted
   files created with this key!!! Rather epxort it!!!
-- Export key: You can export the key and replace it with an other key or
   to share it with other using this program. This allows enryption of all
   files created with this key
-- Supported encryption - file extensions - e.g.: txt, csv, non-type-files,
   py, c, java, sh, xml, ...
"""

comm="""
-- end/e:   end program
-- ef:      encrypt file
-- df:      decrypt file
-- exp:     export key to another directory
-- r:       remove key and/or password
-- rc:      remove encrypted file again
-- s:       check if key and password are in directory
"""

#file-extensions
"""
-- cr: encrypted file (all encrypted files: *.cr)
"""

#get path of ~/.bin/pycr00
pth="/"+str(sys.argv[0].split("/")[1])+"/"+str(sys.argv[0].split("/")[2])+"/.bin/pycr00/"

#create directorys if not existing
try:
	os.system("mkdir -v -p "+str(pth))
except:
	pass

#color class
os.system("") #system call
class col_style():
	col_blue="\033[34m"
	col_cyan="\033[96m"
	col_red="\033[31m"
	col_end="\033[0m" #end color-scheme

#generate key (if not exists)
if os.path.isfile(pth+"mkey.key"):
	pass #making sure there is no key available in directory
else:
	print("No key found -> c: create new key, i: import existing key")
	inp_cik=input(col_style.col_cyan+">> "+col_style.col_end)
	if str(inp_cik)=="c":
		ky=ft.generate_key()
		f_ky=open(pth+"mkey.key","wb").write(ky)
	if str(inp_cik)=="i":
		print("path of key you want to import -> e.g. ~/Documents (home: ~)")
		inp_imp=input(col_style.col_cyan+">> "+col_style.col_end)
		os.system("mv "+str(inp_imp)+"/mkey.key ~/.bin/pycr00")

#return key for encrytion and decryption
def ret_key():
	return open(pth+"mkey.key","rb").read()

#create Master-Password
def ma_pwd():
	inp_mk=getpass("Enter new password: ") #hide password
	#create sha256 from password
	SHA_PW=hlb.sha256(str(inp_mk).encode('utf-8')).hexdigest()
	if os.path.isfile(pth+"sha256"):
		pass #making sure there is no sha available in directory
	else:
		f_sha=open(pth+"sha256","w").write(str(SHA_PW))
		print("password created, restart") ; exit() #export sha to root before exit?!

#compare password to enter program
def comp_mpw():
	inp_ky=getpass("Enter password: ") #hide passwort
	#create sha256 of password to compare
	global sha_comp
	sha_comp=hlb.sha256(str(inp_ky).encode('utf-8')).hexdigest()
	#compare password with sha256
	f_sha=open(pth+"sha256","r").read()
	if str(f_sha)==str(sha_comp):
		pass
	else: print("Wrong password!!!") ; exit()

#return sha256 for comparing
def sha256_ret():
	return open(pth+"sha256","r").read()

#open file to encrypt
def enc_file():
	sha_check=sha256_ret()
	if str(sha_check)==str(sha_comp):
		try:
			print("path/file to encrypt (e.g. ~/Documents/test.txt)")
			inp_fn=input(col_style.col_cyan+">> "+col_style.col_end)
			os.system("cp "+str(inp_fn)+" "+pth)
			f_na=str(inp_fn).split("/")[-1] #get filename
			spl=str(inp_fn).split("/")[0:][:-1] ; pthName="/".join(spl) #path of file
		except:
			print("directory or filename does not exist!!!")
		try:
			#enryption
			of=open(pth+f_na,"r").readlines()
			for l in of:
				r_ky=ret_key() #get generated key
				fec=str(l).encode()
				#create token and encrypt
				fe=ft(r_ky)
				to=fe.encrypt(fec)
				wf=open(pth+f_na+".cr","ab").write(to)
				wf_n=open(pth+f_na+".cr","a").write("\n")
			os.system("mv "+str(pth+f_na)+".cr"+" "+str(pthName))
			os.remove(str(pth+f_na))
			inp_rm=input("remove original (unencrypted) file? [y/N]: ")
			if str(inp_rm)=="y":
				os.system("rm "+str(inp_fn))
		except FileNotFoundError:
			pass
		except IsADirectoryError:
			print("path/directory is missing!!!")
		except UnicodeDecodeError:
			print("File-type not supported!!!")
			os.system("rm "+str(pth+f_na))
	else: exit()

#open file to decrypt
def dec_file():
	sha_check=sha256_ret()
	if str(sha_check)==str(sha_comp):
		try:
			print("path/file to decrypt (e.g. ~/Documents/test.txt.cr)")
			global inp_fn
			inp_fn=input(col_style.col_cyan+">> "+col_style.col_end)
			os.system("cp "+str(inp_fn)+" "+pth)
			f_na=str(inp_fn).split("/")[-1] #get filename + extension
			f_ne=str(f_na).split(".")[:-1] ; fiName=".".join(f_ne) #get filename without .cr
			spl=str(inp_fn).split("/")[0:][:-1] ; pthName="/".join(spl) #path of file
		except:
			print("directory or filename does not exist!!!")
		try:
			of=open(pth+f_na,"rb").readlines()
			for l in of:
				r_ky=ret_key() #get generated key
				fe=ft(r_ky)
				#decrypt token
				dto=fe.decrypt(l)
				sp1=str(dto)[2:]
				sp2=str(sp1)[:-3]
				wf=open(pth+fiName,"a").write(sp2)
				wf_n=open(pth+fiName,"a").write("\n")
			#move file back to directory
			os.system("mv "+str(pth+fiName)+" "+str(pthName))
			#delete '.cr-file' in ~/.bin/pycr00
			os.remove(str(pth+f_na))
		except:
			print("non-encrypted file or key/file-extension 'cr' is missing!!!")
			#check and delete files with non .cr-extension in ~/.bin/pycr00
			if os.path.isfile(str(pth+f_na)):
				os.remove(str(pth+f_na))
	else: exit()

#create new password-database
def wr_dbs():
#password-db columns: name, password, link/plattform, comments
	try:
		inp_na=input("Name of database: ")
		dbn=open(pth+str(inp_na)+".txt","wb")
		print("New file created in "+pth)
	except:
		print("Syntax-Error")

#remove key or/and master-pw
def rem_kypw():
	print("k: remove key, p: remove password")
	inp_kp=input(col_style.col_cyan+">> "+col_style.col_end)
	if str(inp_kp)=="k":
		inp_rmk=input("Are you sure you want to remove current key? [y/N]: ")
		if str(inp_rmk)=="y":
			os.system("rm "+str(pth)+"/mkey.key") ; print(col_style.col_red+"key was removed!!!"+col_style.col_end)
	if str(inp_kp)=="p":
		inp_rmp=input("Are you sure you want to remove current password? [y/N]: ")
		if str(inp_rmp)=="y":
			os.system("rm "+str(pth)+"/sha256") ; print(col_style.col_red+"password was removed!!!"+col_style.col_end)

#export keys
def imp_exp():
	print("Path to move key (e.g. ~/Documents)")
	inp_exp=input(col_style.col_cyan+">> "+col_style.col_end)
	inp_mv=input("m: move, cm: copy and move >> ")
	if str(inp_mv)=="m":
		os.system("cd ~/.bin/pycr00 && mv mkey.key "+str(inp_exp))
		print("key successfully moved to "+str(inp_exp))
	if str(inp_mv)=="cm":
		os.system("cd ~/.bin/pycr00 && cp mkey.key "+str(inp_exp))
		print("key successfully copied to "+str(inp_exp))

def rem_encr():
	try:
		inp_rc=input("Do you want to remove the encrypted file again? [y/N]: ")
		if str(inp_rc)=="y":
			os.system("rm "+str(inp_fn)[:-3])
	except:
		print("function is empty, no value!!!")	

#show all files in directory ~/.bin/pycr00 (should only be mkey and md5_sum)
def show_fil():
	os.chdir(pth) #change directory
	print(gl.glob("*")) #get all

#create Master-Password if not exists
#-> else: Enter program with created (existing) password
if os.path.isfile(pth+"sha256"):
    comp_mpw()
else:
    ma_pwd()

#import/export key/password
#info-line
print("-- i: shows program information")
print("-- h: shows commands")
print("*** to skip commands press enter ***")
#options
inp=""
while str(inp)!="end":
	inp=input(col_style.col_cyan+"command >> "+col_style.col_end)
	if str(inp)=="e":
		exit()
	elif str(inp)=="i":
		print(info)
	elif str(inp)=="h":
		print(comm)
	elif str(inp)=="ef":
		enc_file()
	elif str(inp)=="df":
		dec_file()
	elif str(inp)=="r":
		rem_kypw()
	elif str(inp)=="exp":
		imp_exp()
	elif str(inp)=="s":
		show_fil()
	elif str(inp)=="rc":
		rem_encr()
