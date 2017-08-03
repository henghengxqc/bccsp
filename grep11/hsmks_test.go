/*
Copyright IBM Corp. 2016 All Rights Reserved.

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
package grep11

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/sw"
)

func TestInvalidStoreKey(t *testing.T) {
	storePath, err := ioutil.TempDir("", "hsmKeystore")
	if err != nil {
		t.Fatalf("Failed gettin a temporary key store path [%s]", err)
	}

	swKS, err := sw.NewFileBasedKeyStore(nil, storePath, false)
	if err != nil {
		t.Fatalf("Failed to initialize software key store: %s", err)
	}

	ks, err := NewHsmBasedKeyStore(storePath, swKS)
	if err != nil {
		t.Fatalf("Failed initiliazing KeyStore [%s]", err)
	}

	err = ks.StoreKey(nil)
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}

	os.RemoveAll(storePath)
}

func TestStoreKey(t *testing.T) {
	storePath, err := ioutil.TempDir("", "hsmKeystore")
	if err != nil {
		t.Fatalf("Failed gettin a temporary key store path [%s]", err)
	}

	swKS, err := sw.NewFileBasedKeyStore(nil, storePath, false)
	if err != nil {
		t.Fatalf("Failed to initialize software key store: %s", err)
	}

	ks, err := NewHsmBasedKeyStore(storePath, swKS)
	if err != nil {
		t.Fatalf("Failed initiliazing KeyStore [%s]", err)
	}

	k, err := currentBCCSP.KeyGen(&bccsp.ECDSAP256KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating ECDSA P256 key [%s]", err)
	}
	if k == nil {
		t.Fatal("Failed generating ECDSA P256 key. Key must be different from nil")
	}

	pubKey, err := k.PublicKey()
	if err != nil {
		t.Fatalf("Failed getting public key [%s]", err)
	}

	err = ks.StoreKey(pubKey)
	if err != nil {
		t.Fatal("Error should be different from nil in this case [%s]", err)
	}

	k2, err := ks.GetKey(k.SKI())
	if err != nil {
		t.Fatalf("Failed getting stored public key [%s]", err)
	}
	if k2.Private() {
		t.Fatalf("Expected public key!")
	}

	err = ks.StoreKey(k)
	if err != nil {
		t.Fatal("Error should be different from nil in this case [%s]", err)
	}

	k3, err := ks.GetKey(k.SKI())
	if err != nil {
		t.Fatalf("Failed getting stored private key [%s]", err)
	}
	if !k3.Private() {
		t.Fatalf("Expected private key!")
	}

	os.RemoveAll(storePath)
}
