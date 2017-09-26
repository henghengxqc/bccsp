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
package utils

/*
#cgo LDFLAGS: -l:libep11.so -ldl
#cgo CFLAGS: -std=c99 -I. -I../../grep11/server/

#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <asm/zcrypt.h>
#include <dlfcn.h>
#include "pkcs11.h"
#include <ep11.h>

#define EP11SHAREDLIB "libep11.so"
#define ZCRYPT_DEVICE "/dev/z90crypt"

#define CK_IBM_XCPQ_DOMAIN              3	// query domain mask
#define CK_IBM_DOM_CURR_WK              2       // current WK is present
#define CK_IBM_DOM_NEXT_WK              4       // pending/next WK present
#define CK_IBM_DOM_COMMITTED_NWK        8       // pending/next WK committed
#define  EP11_KEYCSUM_BYTES		32

#define MAX_DOMAINS (16 * 85)
 
typedef CK_RV (*m_init_t)(void); 
typedef CK_RV (*m_get_ep11_info_t)(CK_VOID_PTR, CK_ULONG_PTR,
				   unsigned int query, unsigned int subquery,
				   uint64_t target); 
 
static m_init_t			dll_m_init; 
static m_get_ep11_info_t	dll_m_get_ep11_info; 


struct ep11_target_t {
	short format;
	short length;
	short apqns[2*MAX_ZDEV_CARDIDS*MAX_ZDEV_DOMAINS];
};

typedef char HashInfo_t;

typedef struct {
        char Id;		// adapter id
        char Dom;		// domain id
        HashInfo_t Hash_curr[32];	// Hash pattern current WK
        char State_curr;	// state [not set, valid]
        HashInfo_t Hash_next[32];	// Hash pattern next WK
        char State_next;	// state [not set, uncommitted, committed]
} EP11_domain_info_t;

void print_data(CK_BYTE *ptr, int len) {
	CK_BYTE i;
	for (i = 0; i < len; i++, ptr++)
		printf("%02x", *ptr);
}

static int card_status(int adapter, int domain, char *hash_curr, char *state_curr,
						char *hash_next, char *state_next) 
{ 
	int rc; 
	struct ep11_target_t target; 
	CK_IBM_DOMAIN_INFO dinf; 
	unsigned long dinf_len = sizeof(dinf); 

	target.format = 0; 
	target.length = 1; 

	rc = dll_m_init(); 
	if (rc != 1) { 
		printf("Initialization failed.\n"); 
		return -1; 
	} 
 
	target.apqns[0] = adapter; 
	target.apqns[1] = domain; 

	rc = dll_m_get_ep11_info((CK_VOID_PTR) &dinf, &dinf_len, 
				 CK_IBM_XCPQ_DOMAIN, 0, 
				 (unsigned long long) &target); 

	if (rc != 0) { 
		printf("Crypto adapter query failed (rc=0x%02x)\n", rc); 
		printf("Please check if the provided adapter/domain id specifies a valid EP11 APQN.\n"); 
		return -1; 
	} 

	memcpy(hash_curr, &dinf.wk[0], EP11_KEYCSUM_BYTES);
	*state_curr = CK_IBM_DOM_CURR_WK & dinf.flags;
	memcpy(hash_next, &dinf.nextwk[0], EP11_KEYCSUM_BYTES);
	*state_next = (CK_IBM_DOM_COMMITTED_NWK | CK_IBM_DOM_NEXT_WK) & dinf.flags;

	return 0; 
}

CK_RV getEP11status(EP11_domain_info_t *EP11_domain_info, long *EP11_domain_info_len)
{
	struct zcrypt_device_matrix zmatrix;
	int rc, dh, i;
	int id, dom, ep11_devs = 0;
        void *lib_ep11;

	memset(&zmatrix, 0, sizeof(struct zcrypt_device_matrix));

	// open ep11 library
        lib_ep11 = dlopen(EP11SHAREDLIB, RTLD_GLOBAL | RTLD_NOW);
        if (!lib_ep11) {
                fprintf(stderr,"ERROR loading shared lib '%s' [%s]", EP11SHAREDLIB, dlerror());
                return CKR_FUNCTION_FAILED;
        }

        dll_m_init = (m_init_t)dlsym(lib_ep11, "m_init");
        dll_m_get_ep11_info = (m_get_ep11_info_t)dlsym(lib_ep11, "m_get_ep11_info");

        if ((dlerror()) != NULL)
                return (EXIT_FAILURE);

	// Open z90crypt device
	dh = open(ZCRYPT_DEVICE, O_RDWR);
	if (dh < 0) {
		printf("Open of z90crypt failed with errno=%d\n", errno);
		return 1;
	}

	if ((rc = ioctl(dh, ZDEVICESTATUS, &zmatrix)) < 0) {
		printf("Zcrypt device status query failed!\n");
		printf("RC/errno of ioctl: %i/%i\n", rc, errno);
		close(dh);
		return 2;
	}

	for (i = 0; i < MAX_ZDEV_ENTRIES; i++) {
		id = (zmatrix.device[i].qid & 0x3f00) >> 8;
		dom = zmatrix.device[i].qid & 0x00ff;

		// building the EP11 target list
		if ((zmatrix.device[i].functions & 0x01) && (zmatrix.device[i].online)) {
			EP11_domain_info[ep11_devs].Id = id;
			EP11_domain_info[ep11_devs].Dom = dom;
			ep11_devs++;
		}

	}
	*EP11_domain_info_len = ep11_devs;

	for (i = 0; i < *EP11_domain_info_len; i++) {
		rc = card_status(EP11_domain_info[i].Id, EP11_domain_info[i].Dom,
				 &EP11_domain_info[i].Hash_curr[0], &EP11_domain_info[i].State_curr,
				 &EP11_domain_info[i].Hash_next[0], &EP11_domain_info[i].State_next);
	}

	close(dh);
	dlclose(lib_ep11);
	return 0;
}
*/
import "C"

import (
	"unsafe"
)

/*
type EP11_domain_info_t struct {
        Id		byte		// adapter id
        Dom		byte		// domain id
        Hash_curr	[16]byte	// Hash pattern current WK
        State_curr	byte		// state [not set, valid]
        Hash_next	[16]byte	// Hash pattern next WK
        State_next	byte		// state [not set, uncommitted, committed]
}
*/

type EP11_domain_info_t C.EP11_domain_info_t
type HashInfo_t C.HashInfo_t
var MAX_DOMAINS = C.MAX_DOMAINS

func GetEP11status(domain_list *EP11_domain_info_t,  domain_list_len *int) C.CK_RV {
	return C.getEP11status(((*C.EP11_domain_info_t)(unsafe.Pointer(domain_list))),
			       ((*C.long)(unsafe.Pointer(domain_list_len))))
}

func GetHashValue(wkHash [32]C.HashInfo_t) ([32]HashInfo_t) {
	var i int
	var hash [32]HashInfo_t

	for i = 0; i < 32; {
		hash[i] = HashInfo_t(wkHash[i])
		i++
	}
	return hash
}

func CompareHash(wkHash1 [32]HashInfo_t, wkHash2 [32]C.HashInfo_t) (bool) {
	var i int

	for i = 0; i < 32; {
		if (C.HashInfo_t(wkHash1[i]) == wkHash2[i]) {
			i++
			continue;
		} else {
			return false
		}
	}
	return true
}

func ValidateDevices(devs []int, len int, ep11_domain_info []EP11_domain_info_t,  ep11_domain_info_len int)([]int, int) {
	var apqn_configured bool
	var i, n int
	var wkHash [32]HashInfo_t
	for n = 2; n < (len / 2); {
		apqn_configured = false
		for i = 0; i < ep11_domain_info_len; {
			if ((int(ep11_domain_info[i].Id) != devs[2 * n]) ||
			    (int(ep11_domain_info[i].Dom) != devs[2 * n + 1])) {
				i++
				continue
			}
			apqn_configured = true
			if (cap(wkHash) == 0) {
				wkHash = GetHashValue(ep11_domain_info[i].Hash_curr)
			} else {
				if (CompareHash(wkHash, ep11_domain_info[i].Hash_curr) == false) {
					/* delete entry from the device list */
					devs = append(devs[:2 * n], devs[2 * n + 2:]...)
					len = len - 2
				}
			}
			i++
		}
		if (!apqn_configured) {
			/* delete entry from device list */
			devs = append(devs[:2 * n], devs[2 * n + 2:]...)
			len = len - 2
		}
		n++
	}
	devs[1] = len - 2 // substract header length
	return devs, len
}
