tcci_helper=./tcti_helper/*.cpp
lib_dir=/usr/local/lib
so = -ltss2-esys -ltss2-mu -ltss2-rc -ltss2-sys -ltss2-tctildr \
	-ltss2-tcti-mssim -ltss2-tcti-tabrmd
flag = -std=c++11

all = $(tcci_helper) -Wall -L=$(lib_dir) $(so) $(flag)


all: random pcr enc_dec nv

.PHONY: clean

random: 
	g++ random_hash.cpp $(all) -o random_hash
pcr: 
	g++ pcr.cpp $(all) -o pcr
enc_dec: 
	g++ encrypt_decrypt_aes.cpp $(all) -o encrypt_decrypt_aes
nv:
	g++ nv_basic.cpp $(all) -o nv_basic


clean:
	rm random_hash
	rm pcr
	rm encrypt_decrypt_aes
	rm nv_basic
