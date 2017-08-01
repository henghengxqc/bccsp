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
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/utils"
)

// NewhsmBasedKeyStore instantiated a file-based key store at a given position.
// The key store can be encrypted if a non-empty password is specifiec.
// It can be also be set as read only. In this case, any store operation
// will be forbidden
func NewHsmBasedKeyStore(path string, fallbackKS bccsp.KeyStore) bccsp.KeyStore {
	ks := &hsmBasedKeyStore{}
	ks.path = path
	ks.KeyStore = fallbackKS
	return ks
}

func newPin() ([]byte, error) {
	const pinLen = 8
	pinLetters := []byte("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

	pin := make([]byte, pinLen)
	_, err := rand.Read(pin)
	if err != nil {
		return nil, fmt.Errorf("Failed on rand.Read() in genPin [%s]", err)
	}

	for i := 0; i < pinLen; i++ {
		index := int(pin[i])
		size := len(pinLetters)
		pin[i] = pinLetters[index%size]
	}
	return pin, nil
}

func newNonce() ([]byte, error) {
	const nonceLen = 1024
	nonce := make([]byte, nonceLen)
	_, err := rand.Read(nonce)
	if err != nil {
		return nil, fmt.Errorf("Failed on rand.Read() in getNonce [%s]", err)
	}
	return nonce, nil
}

// hsmBasedKeyStore is a folder-based KeyStore.
// Each key is stored in a separated file whose name contains the key's SKI
// and flags to identity the key's type. All the keys are stored in
// a folder whose path is provided at initialization time.
// The KeyStore can be initialized with a password, this password
// is used to encrypt and decrypt the files storing the keys.
// A KeyStore can be read only to avoid the overwriting of keys.
type hsmBasedKeyStore struct {
	bccsp.KeyStore
	path string

	// Sync
	m sync.Mutex
}

// Init initializes this KeyStore with a password, a path to a folder
// where the keys are stored and a read only flag.
// Each key is stored in a separated file whose name contains the key's SKI
// and flags to identity the key's type.
// If the KeyStore is initialized with a password, this password
// is used to encrypt and decrypt the files storing the keys.
// The pwd can be nil for non-encrypted KeyStores. If an encrypted
// key-store is initialized without a password, then retrieving keys from the
// KeyStore will fail.
// A KeyStore can be read only to avoid the overwriting of keys.
func (ks *hsmBasedKeyStore) Init() ([]byte, []byte, error) {
	_, err := os.Stat(ks.path)
	if os.IsNotExist(err) {
		return nil, nil, fmt.Errorf("Cannot find keystore directory %s", ks.path)
	}

	var pin, nonce []byte
	pinPath := ks.getPathForAlias("pin", "nonce")
	_, err = os.Stat(pinPath)
	if os.IsNotExist(err) {
		pin, err := newPin()
		if err != nil {
			return nil, nil, fmt.Errorf("Could not generate pin %s", err)
		}
		nonce, err := newNonce()
		if err != nil {
			return nil, nil, fmt.Errorf("Could not generate nonce %s", err)
		}

		pinNnonce := pem.EncodeToMemory(
			&pem.Block{
				Type:  "PIN",
				Bytes: pin,
			})

		pinNnonce = append(pinNnonce, pem.EncodeToMemory(
			&pem.Block{
				Type:  "NONCE",
				Bytes: nonce,
			})...)

		err = ioutil.WriteFile(pinPath, pinNnonce, 0700)
		if err != nil {
			logger.Fatalf("Failed storing pin and nonce: [%s]", err)
		}

	} else {
		raw, err := ioutil.ReadFile(pinPath)
		if err != nil {
			logger.Fatalf("Failed loading pin and nonce: [%s].", err)
		}
		block, rest := pem.Decode(raw)
		if block == nil || block.Type != "PIN" {
			logger.Fatalf("failed to decode PEM block containing pin")
		}
		pin = block.Bytes
		block, _ = pem.Decode(rest)
		if block == nil || block.Type != "NONCE" {
			logger.Fatalf("failed to decode PEM block containing pin")
		}
		nonce = block.Bytes
	}

	return pin, nonce, nil
}

// ReadOnly returns true if this KeyStore is read only, false otherwise.
// If ReadOnly is true then StoreKey will fail.
func (ks *hsmBasedKeyStore) ReadOnly() bool {
	return false
}

// GetKey returns a key object whose SKI is the one passed.
func (ks *hsmBasedKeyStore) GetKey(ski []byte) (k bccsp.Key, err error) {
	// Validate arguments
	if len(ski) == 0 {
		return nil, errors.New("Invalid SKI. Cannot be of zero length.")
	}

	suffix := ks.getSuffix(hex.EncodeToString(ski))

	switch suffix {
	case "sk":
		// Load the private key
		key, err := ks.loadPrivateKey(hex.EncodeToString(ski))
		if err != nil {
			return nil, fmt.Errorf("Failed loading secret key [%x] [%s]", ski, err)
		}

		switch key.(type) {
		case *ecdsa.PrivateKey:
			return &ecdsaPrivateKey{key.(*ecdsa.PrivateKey)}, nil
		}
	case "pk":
		// Load the public key
		key, err := ks.loadPublicKey(hex.EncodeToString(ski))
		if err != nil {
			return nil, fmt.Errorf("Failed loading public key [%x] [%s]", ski, err)
		}

		switch key.(type) {
		case *ecdsa.PublicKey:
			return &ecdsaPublicKey{key.(*ecdsa.PublicKey)}, nil
		}
	}

	return ks.KeyStore.GetKey(ski)
}

// StoreKey stores the key k in this KeyStore.
// If this KeyStore is read only then the method will fail.
func (ks *hsmBasedKeyStore) StoreKey(k bccsp.Key) (err error) {
	if ks.readOnly {
		return errors.New("Read only KeyStore.")
	}

	if k == nil {
		return errors.New("Invalid key. It must be different from nil.")
	}
	switch k.(type) {
	case *ecdsaPrivateKey:
		kk := k.(*ecdsaPrivateKey)

		err = ks.storePrivateKey(hex.EncodeToString(k.SKI()), kk.)
		if err != nil {
			return fmt.Errorf("Failed storing ECDSA private key [%s]", err)
		}
		
		err = ks.storePrivateKey(hex.EncodeToString(k.SKI()), kk.privKey)
		if err != nil {
			return fmt.Errorf("Failed storing ECDSA private key [%s]", err)
		}

	case *ecdsaPublicKey:
		kk := k.(*ecdsaPublicKey)

		err = ks.storePublicKey(hex.EncodeToString(k.SKI()), kk.pubKey)
		if err != nil {
			return fmt.Errorf("Failed storing ECDSA public key [%s]", err)
		}

	default:
		ks.KeyStore.StoreKey(k)
	}

	return
}

func (ks *hsmBasedKeyStore) getSuffix(alias string) string {
	files, _ := ioutil.ReadDir(ks.path)
	for _, f := range files {
		if strings.HasPrefix(f.Name(), alias) {
			if strings.HasSuffix(f.Name(), "sk") {
				return "sk"
			}
			if strings.HasSuffix(f.Name(), "pk") {
				return "pk"
			}
			if strings.HasSuffix(f.Name(), "key") {
				return "key"
			}
			break
		}
	}
	return ""
}

func (ks *hsmBasedKeyStore) storePrivateKey(alias string, raw []byte) error {
	rawKey, err := utils.PrivateKeyToPEM(privateKey, ks.pwd)
	if err != nil {
		logger.Errorf("Failed converting private key to PEM [%s]: [%s]", alias, err)
		return err
	}

	err = ioutil.WriteFile(ks.getPathForAlias(alias, "sk"), rawKey, 0700)
	if err != nil {
		logger.Errorf("Failed storing private key [%s]: [%s]", alias, err)
		return err
	}

	return nil
}

func (ks *hsmBasedKeyStore) storePublicKey(alias string, publicKey interface{}) error {
	rawKey, err := utils.PublicKeyToPEM(publicKey, ks.pwd)
	if err != nil {
		logger.Errorf("Failed converting public key to PEM [%s]: [%s]", alias, err)
		return err
	}

	err = ioutil.WriteFile(ks.getPathForAlias(alias, "pk"), rawKey, 0700)
	if err != nil {
		logger.Errorf("Failed storing private key [%s]: [%s]", alias, err)
		return err
	}

	return nil
}

func (ks *hsmBasedKeyStore) loadPrivateKey(alias string) (interface{}, error) {
	path := ks.getPathForAlias(alias, "sk")
	logger.Debugf("Loading private key [%s] at [%s]...", alias, path)

	raw, err := ioutil.ReadFile(path)
	if err != nil {
		logger.Errorf("Failed loading private key [%s]: [%s].", alias, err.Error())

		return nil, err
	}

	privateKey, err := utils.PEMtoPrivateKey(raw, ks.pwd)
	if err != nil {
		logger.Errorf("Failed parsing private key [%s]: [%s].", alias, err.Error())

		return nil, err
	}

	return privateKey, nil
}

func (ks *hsmBasedKeyStore) loadPublicKey(alias string) (interface{}, error) {
	path := ks.getPathForAlias(alias, "pk")
	logger.Debugf("Loading public key [%s] at [%s]...", alias, path)

	raw, err := ioutil.ReadFile(path)
	if err != nil {
		logger.Errorf("Failed loading public key [%s]: [%s].", alias, err.Error())

		return nil, err
	}

	privateKey, err := utils.PEMtoPublicKey(raw, ks.pwd)
	if err != nil {
		logger.Errorf("Failed parsing private key [%s]: [%s].", alias, err.Error())

		return nil, err
	}

	return privateKey, nil
}

func (ks *hsmBasedKeyStore) getPathForAlias(alias, suffix string) string {
	return filepath.Join(ks.path, alias+"_"+suffix)
}
