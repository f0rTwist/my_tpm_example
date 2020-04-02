tcci_helper=./tcti_helper/*.c
lib_dir=/usr/local/lib
so = -ltss2-esys -ltss2-mu -ltss2-rc -ltss2-sys -ltss2-tctildr \
	-ltss2-tcti-mssim -ltss2-tcti-tabrmd

all: random pcr enc_dec nv

.PHONY: clean

random: 
	gcc random_hash.c $(tcci_helper) -Wall -L=$(lib_dir) $(so) -o random_hash
pcr: 
	gcc -g pcr.c $(tcci_helper) -Wall -L=$(lib_dir) $(so) -o pcr
enc_dec: 
	gcc -g encrypt_decrypt_aes.c $(tcci_helper) -Wall -L=$(lib_dir) $(so) -o encrypt_decrypt_aes
nv:
	gcc -g nv_basic.c $(tcci_helper) -Wall -L=$(lib_dir) $(so) -o nv_basic


clean:
	rm random_hash
	rm pcr
	rm encrypt_decrypt_aes
	nv_basic
