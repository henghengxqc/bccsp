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
#cgo LDFLAGS: -l:libep11.so
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


CK_RV login ( CK_UTF8CHAR_PTR pin,      CK_ULONG pinlen,
            const unsigned char *nonce,     size_t nlen,
                  unsigned char *pinblob,   size_t *pinbloblen);

CK_RV logout ( CK_UTF8CHAR_PTR pin,      CK_ULONG pinlen);
*/
import "C"

import (
	"bufio"
	"encoding/base64"
	"io"
	"os"
	"sync"
	"unsafe"
)

func cleanKnownSessions(store string) error {
	logger.Infof("Looking for existing sessions in %s", store)
	var _, err = os.Stat(store)
	if os.IsNotExist(err) {
		logger.Infof("No list of existing sessions found in %s", store)
		return err
	}

	f, err := os.Open(store)
	if err != nil {
		logger.Infof("Error opening list of known sessions: %v\n", err)
		return err
	}

	defer f.Close()
	defer os.Remove(store)

	r := bufio.NewReader(f)

	var line string
	counter := 0

	for {
		line, err = r.ReadString('\n')
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		pinblob, err := base64.StdEncoding.DecodeString(line)
		if err != nil {
			logger.Warningf("Decode error: %s", err)
			return err
		}

		logger.Infof("Logging out EP11 session %s...>> ", line[:16])
		rv := C.logout((*C.CK_UTF8CHAR)(unsafe.Pointer(&pinblob[0])), C.CK_ULONG(len(pinblob)))
		if rv != C.CKR_OK {
			logger.Errorf("m_Logout returned 0x%x\n%s", rv, line)
			continue
		}
		counter++
	}

	logger.Infof("Successfully logged out %d session(s)", counter)
	return nil
}

var lock sync.Mutex

func logSession(store string, pin []byte) error {
	lock.Lock()
	defer lock.Unlock()

	var file *os.File
	var _, err = os.Stat(store)
	if os.IsNotExist(err) {
		file, err = os.OpenFile(store, os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			logger.Fatalf("Could not create file %s to record PIN [%s]", store, err)
		}
	} else {
		file, err = os.OpenFile(store, os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			logger.Fatalf("Could not open file %s to record PIN [%s]", store, err)
		}
	}

	encodedpin := base64.StdEncoding.EncodeToString(pin)
	_, err = file.WriteString(encodedpin)
	logger.Debugf(">>>>>> Logging %s [%s]", encodedpin, err)
	file.Write([]byte("\n"))
	file.Sync()
	file.Close()
	return nil
}
