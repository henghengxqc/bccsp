/*
Copyright IBM Corp. 2017 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package server

/*
#cgo LDFLAGS: -l:libgrep11.so
#cgo CFLAGS: -std=c99 -I.

#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)

#include <unistd.h>
#include "pkcs11.h"

#include <stdint.h>
#include <ep11.h>

#include <string.h>
#include <stdio.h>


static uint64_t ep11tok_target = 0x0000000000000000ull;
static unsigned char *ep11_pin_blob = NULL;
static CK_ULONG ep11_pin_blob_len = 0;

CK_RV login ( CK_UTF8CHAR_PTR pin,      CK_ULONG pinlen,
            const unsigned char *nonce,     size_t nlen,
                  unsigned char *pinblob,   size_t *pinbloblen) {
	return m_Login(pin, pinlen, nonce, nlen,
			pinblob, pinbloblen,
			(uint64_t)(long)&ep11tok_target);
}

CK_RV logout ( CK_UTF8CHAR_PTR pin,      CK_ULONG pinlen) {

	return m_Logout(pin, pinlen,
			(uint64_t)(long)&ep11tok_target);
}

CK_RV generateKeyPair (     unsigned char *oid,       size_t olen,
                      const unsigned char *pinblob,       size_t pinbloblen,
                            unsigned char *key,       size_t *klen,
                            unsigned char *pubkey,    size_t *pklen) {

	CK_BBOOL ltrue = CK_TRUE;
	CK_ATTRIBUTE prva[] = {
	    { CKA_SIGN,        &ltrue, sizeof(ltrue) },
	} ;
	CK_ATTRIBUTE puba[] = {                       // keep OID at index 0
	    { CKA_EC_PARAMS,   oid,    olen },
	    { CKA_VERIFY,      &ltrue, sizeof(ltrue) },
	} ;
	CK_MECHANISM mech = {
		CKM_EC_KEY_PAIR_GEN, NULL, 0
	};

	return m_GenerateKeyPair(&mech,
		   puba, sizeof(puba)/sizeof(CK_ATTRIBUTE),
		   prva, sizeof(prva)/sizeof(CK_ATTRIBUTE),
		   pinbloblen == 0 ? ep11_pin_blob : pinblob, pinbloblen,
		   key, klen, pubkey, pklen,
		   (uint64_t)(long)&ep11tok_target);
}

CK_RV signSingle (const unsigned char *key,      size_t klen,
                              CK_BYTE_PTR hash,    CK_ULONG hlen,
                              CK_BYTE_PTR sig, CK_ULONG_PTR slen) {
	CK_MECHANISM mech = {
			CKM_ECDSA, NULL, 0
		};

	return m_SignSingle(key, klen,
			&mech, hash, hlen,
			sig, slen,
			(uint64_t)(long)&ep11tok_target);
}

CK_RV verifySingle (const unsigned char *key,      size_t klen,
                              CK_BYTE_PTR hash,    CK_ULONG hlen,
                              CK_BYTE_PTR sig,     CK_ULONG slen) {
	CK_MECHANISM mech = {
			CKM_ECDSA, NULL, 0
		};

	return  m_VerifySingle(key, klen, &mech, hash, hlen,
            sig, slen, (uint64_t)(long)&ep11tok_target);;
}
*/
import "C"
