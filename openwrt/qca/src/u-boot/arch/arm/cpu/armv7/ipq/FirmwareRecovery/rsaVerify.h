#ifndef RSA_VERIFY_H_
#define RSA_VERIFY_H_

#include "bigNumber.h"

typedef struct _MY_PUBLICKEYSTRUC {
	char bType;
	char bVersion;
	short reserved;
	unsigned long aiKeyAlg;
}MY_BLOBHEADER, MY_PUBLICKEYSTRUC;

typedef struct _MY_RSAPUBKEY {
	unsigned long magic;
	unsigned long bitlen;
	unsigned long pubexp;
} MY_RSAPUBKEY;

typedef struct _MY_RSA_PUBLICK_BLOB{
	MY_PUBLICKEYSTRUC blob_header;
	MY_RSAPUBKEY      rsa_pub_key;
}MY_RSA_PUBLICK_BLOB;


struct RSAKey {
	int bits;
	int bytes;
	Bignum modulus;
	Bignum exponent;
	Bignum private_exponent;
	Bignum p;
	Bignum q;
	Bignum iqmp;
	char *comment;
};


#define CHAR64(c) (((c) < 0 || (c) > 127) ? -1 : index_64[(c)])

extern int check_cloud(unsigned char *buf, int len);

#endif

