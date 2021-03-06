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
	"bytes"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"hash"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"testing"
	"time"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/signer"
	"github.com/hyperledger/fabric/bccsp/sw"
	"github.com/hyperledger/fabric/bccsp/utils"
	"github.com/op/go-logging"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/vpaprots/bccsp/grep11/server"
	"golang.org/x/crypto/sha3"
)

const (
	ADDRESS = "localhost"
	PORT    = "6789"
)

var (
	currentKS         bccsp.KeyStore
	currentBCCSP      bccsp.BCCSP
	currentTestConfig testConfig
)

type testConfig struct {
	securityLevel int
	hashFamily    string
	softVerify    bool
	noKeyImport   bool
}

func TestMain(m *testing.M) {
	// Activate DEBUG level to cover listAttrs function
	logging.SetLevel(logging.DEBUG, "bccsp_ep11")

	storePath, err := ioutil.TempDir("", "hsmKeystore")
	if err != nil {
		fmt.Printf("Failed getting a temporary key store path [%s]", err)
		os.Exit(-1)
	}
	fmt.Printf("Creating a keystore in %s\n", storePath)

	ks, err := sw.NewFileBasedKeyStore(nil, storePath, false)
	if err != nil {
		fmt.Printf("Failed initiliazing KeyStore [%s]\n", err)
		os.Exit(-1)
	}
	currentKS = ks

	tests := []testConfig{
		{256, "SHA2", true, true},
		{256, "SHA3", true, true},
		// No HSM Verify implemented yet
		{256, "SHA3", false, true},
		/*{384, "SHA2", false, true},
		{384, "SHA3", false, true},
		{384, "SHA2", true, true},
		{384, "SHA3", true, true},*/
	}

	opts := GREP11Opts{
		Address: ADDRESS,
		Port:    PORT,
	}

	pinStorePath, err := ioutil.TempFile("", "hsmPinstore")
	if err != nil {
		fmt.Printf("Failed getting a temporary key store path [%s]", err)
		os.Exit(-1)
	}

	viper.SetDefault("grep11.serverShutdownSecs", 60)
	viper.SetDefault("grep11.debugEnabled", true)

	server.CreateTestServer(opts.Address, opts.Port, pinStorePath.Name(), 0)

	for _, config := range tests {
		var err error
		currentTestConfig = config

		opts.HashFamily = config.hashFamily
		opts.SecLevel = config.securityLevel
		opts.SoftVerify = config.softVerify
		opts.FileKeystore = &FileKeystoreOpts{storePath}
		currentBCCSP, err = New(opts, currentKS)
		if err != nil {
			fmt.Printf("Failed initiliazing BCCSP at [%+v]: [%s]\n", opts, err)
			os.Exit(-1)
		}

		ret := m.Run()
		if ret != 0 {
			fmt.Printf("Failed testing at [%+v]", opts)
			os.Exit(-1)
		}
	}
	os.RemoveAll(storePath)
	os.Exit(0)
}

func TestHSMKeyStoreInvalidPubKey(t *testing.T) {
	hsmKs := &hsmBasedKeyStore{}

	err := hsmKs.storePublicKey("", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Failed converting public key to PEM")
}

func TestHSMKeyStoreInvalidPrivateKey(t *testing.T) {
	t.SkipNow()
	hsmKs := &hsmBasedKeyStore{}

	err := hsmKs.storePrivateKey("baddir", []byte{0})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Failed storing private key")
}

func TestHSMKeyStoreReadMethod(t *testing.T) {
	hsmKS := &hsmBasedKeyStore{}

	readOnly := hsmKS.ReadOnly()
	assert.Equal(t, readOnly, false)
}

func TestPubToKeyBlobNilPubKey(t *testing.T) {
	_, err := pubKeyToBlob(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Value of Public Key was nil")
}

func TestSHA3InvalidSecurityLevel(t *testing.T) {
	conf := &config{}

	err := conf.setSecurityLevelSHA3(888)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Security level not supported")
}

func TestSHA2InvalidSecurityLevel(t *testing.T) {
	conf := &config{}

	err := conf.setSecurityLevelSHA2(999)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Security level not supported")
}

func TestNewInvalidHSMKeyStorePath(t *testing.T) {
	testOpts := GREP11Opts{
		Address:      ADDRESS,
		Port:         PORT,
		HashFamily:   "SHA2",
		SecLevel:     256,
		SoftVerify:   true,
		FileKeystore: &FileKeystoreOpts{""},
	}
	_, err := New(testOpts, currentKS)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Cannot find keystore directory")
}

func TestNewNilOpts(t *testing.T) {
	_, err := New(GREP11Opts{}, currentKS)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Failed initializing configuration")
}

func TestNewNilFallbackKS(t *testing.T) {
	testStorePath, err := ioutil.TempDir("", "testKeystore")
	if err != nil {
		fmt.Printf("Failed getting temporary key store path [%s]", err)
		os.Exit(-1)
	}
	defer os.RemoveAll(testStorePath)

	testOpts := GREP11Opts{
		Address:      ADDRESS,
		Port:         PORT,
		HashFamily:   "SHA2",
		SecLevel:     256,
		SoftVerify:   true,
		FileKeystore: &FileKeystoreOpts{testStorePath},
	}
	_, err = New(testOpts, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Failed initializing fallback SW BCCSP")
}

func TestNewNilFileKeyStore(t *testing.T) {
	testOpts := GREP11Opts{
		Address:      ADDRESS,
		Port:         PORT,
		HashFamily:   "SHA2",
		SecLevel:     256,
		SoftVerify:   true,
		FileKeystore: nil,
	}
	_, err := New(testOpts, currentKS)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "FileKeystore is required to use GREP11 CSP")
}

func TestNewInvalidAddressPort(t *testing.T) {
	testStorePath, err := ioutil.TempDir("", "testKeystore")
	if err != nil {
		fmt.Printf("Failed getting a temporary key store path [%s]", err)
		os.Exit(-1)
	}
	defer os.RemoveAll(testStorePath)

	testOpts := GREP11Opts{
		Address:      "badhost",
		Port:         PORT,
		HashFamily:   "SHA2",
		SecLevel:     256,
		SoftVerify:   true,
		FileKeystore: &FileKeystoreOpts{testStorePath},
	}

	t.Logf("GREP11Opts: [%+v]\n", testOpts)

	// Test invalid host
	_, err = New(testOpts, currentKS)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Failed connecting to GREP11 manager")

	//Test invalid port
	testOpts.Port = "badport"

	t.Logf("GREP11Opts: [%+v]\n", testOpts)

	_, err = New(testOpts, currentKS)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Failed connecting to GREP11 manager")
}

func TestInvalidSKI(t *testing.T) {
	k, err := currentBCCSP.GetKey(nil)
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}
	if k != nil {
		t.Fatal("Return value should be equal to nil in this case")
	}

	k, err = currentBCCSP.GetKey([]byte{0, 1, 2, 3, 4, 5, 6})
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}
	if k != nil {
		t.Fatal("Return value should be equal to nil in this case")
	}
}

func TestGenerateECKeyInvalidCurve(t *testing.T) {
	_, err := currentBCCSP.(*impl).generateECKey(nil, true)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Could not marshal OID")
}

func TestKeyGenECDSAOpts(t *testing.T) {
	// Curve P256
	k, err := currentBCCSP.KeyGen(&bccsp.ECDSAP256KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating ECDSA P256 key [%s]", err)
	}
	if k == nil {
		t.Fatal("Failed generating ECDSA P256 key. Key must be different from nil")
	}
	if !k.Private() {
		t.Fatal("Failed generating ECDSA P256 key. Key should be private")
	}
	if k.Symmetric() {
		t.Fatal("Failed generating ECDSA P256 key. Key should be asymmetric")
	}

	ecdsaKey := k.(*ecdsaPrivateKey).pub
	if elliptic.P256() != ecdsaKey.pub.Curve {
		t.Fatal("P256 generated key in invalid. The curve must be P256.")
	}

	// Test PublicKey Method
	ecdsaPubKey, err := k.(*ecdsaPrivateKey).pub.PublicKey()
	assert.Equal(t, ecdsaPubKey, ecdsaKey)

	// Curve P384
	k, err = currentBCCSP.KeyGen(&bccsp.ECDSAP384KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating ECDSA P384 key [%s]", err)
	}
	if k == nil {
		t.Fatal("Failed generating ECDSA P384 key. Key must be different from nil")
	}
	if !k.Private() {
		t.Fatal("Failed generating ECDSA P384 key. Key should be private")
	}
	if k.Symmetric() {
		t.Fatal("Failed generating ECDSA P384 key. Key should be asymmetric")
	}

	ecdsaKey = k.(*ecdsaPrivateKey).pub
	if elliptic.P384() != ecdsaKey.pub.Curve {
		t.Fatal("P256 generated key in invalid. The curve must be P384.")
	}
}

func TestKeyGenRSAOpts(t *testing.T) {
	// 1024
	k, err := currentBCCSP.KeyGen(&bccsp.RSA1024KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating RSA 1024 key [%s]", err)
	}
	if k == nil {
		t.Fatal("Failed generating RSA 1024 key. Key must be different from nil")
	}
	if !k.Private() {
		t.Fatal("Failed generating RSA 1024 key. Key should be private")
	}
	if k.Symmetric() {
		t.Fatal("Failed generating RSA 1024 key. Key should be asymmetric")
	}

	// 2048
	k, err = currentBCCSP.KeyGen(&bccsp.RSA2048KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating RSA 2048 key [%s]", err)
	}
	if k == nil {
		t.Fatal("Failed generating RSA 2048 key. Key must be different from nil")
	}
	if !k.Private() {
		t.Fatal("Failed generating RSA 2048 key. Key should be private")
	}
	if k.Symmetric() {
		t.Fatal("Failed generating RSA 2048 key. Key should be asymmetric")
	}
}

func TestKeyGenAESOpts(t *testing.T) {
	// AES 128
	k, err := currentBCCSP.KeyGen(&bccsp.AES128KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating AES 128 key [%s]", err)
	}
	if k == nil {
		t.Fatal("Failed generating AES 128 key. Key must be different from nil")
	}
	if !k.Private() {
		t.Fatal("Failed generating AES 128 key. Key should be private")
	}
	if !k.Symmetric() {
		t.Fatal("Failed generating AES 128 key. Key should be symmetric")
	}

	// AES 192
	k, err = currentBCCSP.KeyGen(&bccsp.AES192KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating AES 192 key [%s]", err)
	}
	if k == nil {
		t.Fatal("Failed generating AES 192 key. Key must be different from nil")
	}
	if !k.Private() {
		t.Fatal("Failed generating AES 192 key. Key should be private")
	}
	if !k.Symmetric() {
		t.Fatal("Failed generating AES 192 key. Key should be symmetric")
	}

	// AES 256
	k, err = currentBCCSP.KeyGen(&bccsp.AES256KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating AES 256 key [%s]", err)
	}
	if k == nil {
		t.Fatal("Failed generating AES 256 key. Key must be different from nil")
	}
	if !k.Private() {
		t.Fatal("Failed generating AES 256 key. Key should be private")
	}
	if !k.Symmetric() {
		t.Fatal("Failed generating AES 256 key. Key should be symmetric")
	}
}

func TestHashOpts(t *testing.T) {
	msg := []byte("abcd")

	// SHA256
	digest1, err := currentBCCSP.Hash(msg, &bccsp.SHA256Opts{})
	if err != nil {
		t.Fatalf("Failed computing SHA256 [%s]", err)
	}

	h := sha256.New()
	h.Write(msg)
	digest2 := h.Sum(nil)

	if !bytes.Equal(digest1, digest2) {
		t.Fatalf("Different SHA256 computed. [%x][%x]", digest1, digest2)
	}

	// SHA384
	digest1, err = currentBCCSP.Hash(msg, &bccsp.SHA384Opts{})
	if err != nil {
		t.Fatalf("Failed computing SHA384 [%s]", err)
	}

	h = sha512.New384()
	h.Write(msg)
	digest2 = h.Sum(nil)

	if !bytes.Equal(digest1, digest2) {
		t.Fatalf("Different SHA384 computed. [%x][%x]", digest1, digest2)
	}

	// SHA3_256O
	digest1, err = currentBCCSP.Hash(msg, &bccsp.SHA3_256Opts{})
	if err != nil {
		t.Fatalf("Failed computing SHA3_256 [%s]", err)
	}

	h = sha3.New256()
	h.Write(msg)
	digest2 = h.Sum(nil)

	if !bytes.Equal(digest1, digest2) {
		t.Fatalf("Different SHA3_256 computed. [%x][%x]", digest1, digest2)
	}

	// SHA3_384
	digest1, err = currentBCCSP.Hash(msg, &bccsp.SHA3_384Opts{})
	if err != nil {
		t.Fatalf("Failed computing SHA3_384 [%s]", err)
	}

	h = sha3.New384()
	h.Write(msg)
	digest2 = h.Sum(nil)

	if !bytes.Equal(digest1, digest2) {
		t.Fatalf("Different SHA3_384 computed. [%x][%x]", digest1, digest2)
	}
}

func TestECDSAKeyGenEphemeral(t *testing.T) {
	k, err := currentBCCSP.KeyGen(&bccsp.ECDSAKeyGenOpts{Temporary: true})
	if err != nil {
		t.Fatalf("Failed generating ECDSA key [%s]", err)
	}
	if k == nil {
		t.Fatal("Failed generating ECDSA key. Key must be different from nil")
	}
	if !k.Private() {
		t.Fatal("Failed generating ECDSA key. Key should be private")
	}
	if k.Symmetric() {
		t.Fatal("Failed generating ECDSA key. Key should be asymmetric")
	}
	raw, err := k.Bytes()
	if err == nil {
		t.Fatal("Failed marshalling to bytes. Marshalling must fail.")
	}
	if len(raw) != 0 {
		t.Fatal("Failed marshalling to bytes. Output should be 0 bytes")
	}
	pk, err := k.PublicKey()
	if err != nil {
		t.Fatalf("Failed getting corresponding public key [%s]", err)
	}
	if pk == nil {
		t.Fatal("Public key must be different from nil.")
	}
}

func TestECDSAPrivateKeySKI(t *testing.T) {

	k, err := currentBCCSP.KeyGen(&bccsp.ECDSAKeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating ECDSA key [%s]", err)
	}

	ski := k.SKI()
	if len(ski) == 0 {
		t.Fatal("SKI not valid. Zero length.")
	}
}

func TestECDSAKeyGenNonEphemeral(t *testing.T) {

	k, err := currentBCCSP.KeyGen(&bccsp.ECDSAKeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating ECDSA key [%s]", err)
	}
	if k == nil {
		t.Fatal("Failed generating ECDSA key. Key must be different from nil")
	}
	if !k.Private() {
		t.Fatal("Failed generating ECDSA key. Key should be private")
	}
	if k.Symmetric() {
		t.Fatal("Failed generating ECDSA key. Key should be asymmetric")
	}
}

func TestECDSAGetKeyBySKI(t *testing.T) {

	k, err := currentBCCSP.KeyGen(&bccsp.ECDSAKeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating ECDSA key [%s]", err)
	}
	k2, err := currentBCCSP.GetKey(k.SKI())
	if err != nil {
		t.Fatalf("Failed getting ECDSA key [%s]", err)
	}
	if k2 == nil {
		t.Fatal("Failed getting ECDSA key. Key must be different from nil")
	}
	if !k2.Private() {
		t.Fatal("Failed getting ECDSA key. Key should be private")
	}
	if k2.Symmetric() {
		t.Fatal("Failed getting ECDSA key. Key should be asymmetric")
	}

	// Check that the SKIs are the same
	if !bytes.Equal(k.SKI(), k2.SKI()) {
		t.Fatalf("SKIs are different [%x]!=[%x]", k.SKI(), k2.SKI())
	}
}

func TestECDSAPublicKeyFromPrivateKey(t *testing.T) {

	k, err := currentBCCSP.KeyGen(&bccsp.ECDSAKeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating ECDSA key [%s]", err)
	}

	pk, err := k.PublicKey()
	if err != nil {
		t.Fatalf("Failed getting public key from private ECDSA key [%s]", err)
	}
	if pk == nil {
		t.Fatal("Failed getting public key from private ECDSA key. Key must be different from nil")
	}
	if pk.Private() {
		t.Fatal("Failed generating ECDSA key. Key should be public")
	}
	if pk.Symmetric() {
		t.Fatal("Failed generating ECDSA key. Key should be asymmetric")
	}
}

func TestECDSAPublicKeyBytes(t *testing.T) {

	k, err := currentBCCSP.KeyGen(&bccsp.ECDSAKeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating ECDSA key [%s]", err)
	}

	pk, err := k.PublicKey()
	if err != nil {
		t.Fatalf("Failed getting public key from private ECDSA key [%s]", err)
	}

	raw, err := pk.Bytes()
	if err != nil {
		t.Fatalf("Failed marshalling ECDSA public key [%s]", err)
	}
	if len(raw) == 0 {
		t.Fatal("Failed marshalling ECDSA public key. Zero length")
	}
}

func TestECDSAPublicKeySKI(t *testing.T) {

	k, err := currentBCCSP.KeyGen(&bccsp.ECDSAKeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating ECDSA key [%s]", err)
	}

	pk, err := k.PublicKey()
	if err != nil {
		t.Fatalf("Failed getting public key from private ECDSA key [%s]", err)
	}

	ski := pk.SKI()
	if len(ski) == 0 {
		t.Fatal("SKI not valid. Zero length.")
	}
}

func TestECDSASign(t *testing.T) {

	k, err := currentBCCSP.KeyGen(&bccsp.ECDSAKeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating ECDSA key [%s]", err)
	}

	msg := []byte("Hello World")

	digest, err := currentBCCSP.Hash(msg, &bccsp.SHAOpts{})
	if err != nil {
		t.Fatalf("Failed computing HASH [%s]", err)
	}

	signature, err := currentBCCSP.Sign(k, digest, nil)
	if err != nil {
		t.Fatalf("Failed generating ECDSA signature [%s]", err)
	}
	if len(signature) == 0 {
		t.Fatal("Failed generating ECDSA key. Signature must be different from nil")
	}

	// Test nil key
	_, err = currentBCCSP.Sign(nil, digest, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid Key. It must not be nil.")

	// Test nil digest
	_, err = currentBCCSP.Sign(k, nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid digest. Cannot be empty.")

	testPubKey, err := k.PublicKey()
	if err != nil {
		t.Fatal("Failed to extract public key.")
	}

	// Test using public key for signing
	_, err = currentBCCSP.Sign(testPubKey, digest, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Cannot sign with a grep11.ecdsaPublicKey")
}

func TestECDSAVerify(t *testing.T) {
	k, err := currentBCCSP.KeyGen(&bccsp.ECDSAKeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating ECDSA key [%s]", err)
	}

	msg := []byte("Hello World")

	digest, err := currentBCCSP.Hash(msg, &bccsp.SHAOpts{})
	if err != nil {
		t.Fatalf("Failed computing HASH [%s]", err)
	}

	signature, err := currentBCCSP.Sign(k, digest, nil)
	if err != nil {
		t.Fatalf("Failed generating ECDSA signature  [%s]", err)
	}

	valid, err := currentBCCSP.Verify(k, signature, digest, nil)
	if err != nil {
		t.Fatalf("Failed verifying ECDSA signature [%s]", err)
	}
	if !valid {
		t.Fatal("Failed verifying ECDSA signature. Signature not valid.")
	}

	pk, err := k.PublicKey()
	if err != nil {
		t.Fatalf("Failed getting corresponding public key [%s]", err)
	}

	valid, err = currentBCCSP.Verify(pk, signature, digest, nil)
	if err != nil {
		t.Fatalf("Failed verifying ECDSA signature [%s]", err)
	}
	if !valid {
		t.Fatal("Failed verifying ECDSA signature. Signature not valid.")
	}

	_, err = currentBCCSP.Verify(nil, signature, digest, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid Key. It must not be nil.")

	_, err = currentBCCSP.Verify(pk, nil, digest, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid signature. Cannot be empty.")

	_, err = currentBCCSP.Verify(pk, signature, nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid digest. Cannot be empty.")

	// Ensure unsupported HSM Verify message occurs here
	/*
	_, err = currentBCCSP.(*impl).verifyP11ECDSA(nil, nil, nil, nil, 0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Remote Verify is currently not supported.")
*/
	// Import the exported public key
	pkRaw, err := pk.Bytes()
	if err != nil {
		t.Fatalf("Failed getting ECDSA raw public key [%s]", err)
	}

	// Store public key
	_, err = currentBCCSP.KeyImport(pkRaw, &bccsp.ECDSAPKIXPublicKeyImportOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed storing corresponding public key [%s]", err)
	}

	pk2, err := currentBCCSP.GetKey(pk.SKI())
	if err != nil {
		t.Fatalf("Failed retrieving corresponding public key [%s]", err)
	}

	valid, err = currentBCCSP.Verify(pk2, signature, digest, nil)
	if err != nil {
		t.Fatalf("Failed verifying ECDSA signature [%s]", err)
	}
	if !valid {
		t.Fatal("Failed verifying ECDSA signature. Signature not valid.")
	}
}

func TestECDSAKeyImportFromExportedKey(t *testing.T) {
	// Generate an ECDSA key
	k, err := currentBCCSP.KeyGen(&bccsp.ECDSAKeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating ECDSA key [%s]", err)
	}

	// Export the public key
	pk, err := k.PublicKey()
	if err != nil {
		t.Fatalf("Failed getting ECDSA public key [%s]", err)
	}

	pkRaw, err := pk.Bytes()
	if err != nil {
		t.Fatalf("Failed getting ECDSA raw public key [%s]", err)
	}

	// Import the exported public key
	pk2, err := currentBCCSP.KeyImport(pkRaw, &bccsp.ECDSAPKIXPublicKeyImportOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed importing ECDSA public key [%s]", err)
	}
	if pk2 == nil {
		t.Fatal("Failed importing ECDSA public key. Return BCCSP key cannot be nil.")
	}

	// Sign and verify with the imported public key
	msg := []byte("Hello World")

	digest, err := currentBCCSP.Hash(msg, &bccsp.SHAOpts{})
	if err != nil {
		t.Fatalf("Failed computing HASH [%s]", err)
	}

	signature, err := currentBCCSP.Sign(k, digest, nil)
	if err != nil {
		t.Fatalf("Failed generating ECDSA signature [%s]", err)
	}

	valid, err := currentBCCSP.Verify(pk2, signature, digest, nil)
	if err != nil {
		t.Fatalf("Failed verifying ECDSA signature [%s]", err)
	}
	if !valid {
		t.Fatal("Failed verifying ECDSA signature. Signature not valid.")
	}
}

func TestECDSAKeyImportFromECDSAPublicKey(t *testing.T) {
	// Generate an ECDSA key
	k, err := currentBCCSP.KeyGen(&bccsp.ECDSAKeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating ECDSA key [%s]", err)
	}

	// Export the public key
	pk, err := k.PublicKey()
	if err != nil {
		t.Fatalf("Failed getting ECDSA public key [%s]", err)
	}

	pkRaw, err := pk.Bytes()
	if err != nil {
		t.Fatalf("Failed getting ECDSA raw public key [%s]", err)
	}

	pub, err := utils.DERToPublicKey(pkRaw)
	if err != nil {
		t.Fatalf("Failed converting raw to ecdsa.PublicKey [%s]", err)
	}

	// Import the ecdsa.PublicKey
	pk2, err := currentBCCSP.KeyImport(pub, &bccsp.ECDSAGoPublicKeyImportOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed importing ECDSA public key [%s]", err)
	}
	if pk2 == nil {
		t.Fatal("Failed importing ECDSA public key. Return BCCSP key cannot be nil.")
	}

	// Sign and verify with the imported public key
	msg := []byte("Hello World")

	digest, err := currentBCCSP.Hash(msg, &bccsp.SHAOpts{})
	if err != nil {
		t.Fatalf("Failed computing HASH [%s]", err)
	}

	signature, err := currentBCCSP.Sign(k, digest, nil)
	if err != nil {
		t.Fatalf("Failed generating ECDSA signature [%s]", err)
	}

	valid, err := currentBCCSP.Verify(pk2, signature, digest, nil)
	if err != nil {
		t.Fatalf("Failed verifying ECDSA signature [%s]", err)
	}
	if !valid {
		t.Fatal("Failed verifying ECDSA signature. Signature not valid.")
	}
}

func TestKeyImportFromX509ECDSAPublicKey(t *testing.T) {
	// Generate an ECDSA key
	k, err := currentBCCSP.KeyGen(&bccsp.ECDSAKeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating ECDSA key [%s]", err)
	}

	// Generate a self-signed certificate
	testExtKeyUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	testUnknownExtKeyUsage := []asn1.ObjectIdentifier{[]int{1, 2, 3}, []int{2, 59, 1}}
	extraExtensionData := []byte("extra extension")
	commonName := "test.example.com"
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Σ Acme Co"},
			Country:      []string{"US"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  []int{2, 5, 4, 42},
					Value: "Gopher",
				},
				// This should override the Country, above.
				{
					Type:  []int{2, 5, 4, 6},
					Value: "NL",
				},
			},
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(1 * time.Hour),

		SignatureAlgorithm: x509.ECDSAWithSHA256,

		SubjectKeyId: []byte{1, 2, 3, 4},
		KeyUsage:     x509.KeyUsageCertSign,

		ExtKeyUsage:        testExtKeyUsage,
		UnknownExtKeyUsage: testUnknownExtKeyUsage,

		BasicConstraintsValid: true,
		IsCA: true,

		OCSPServer:            []string{"http://ocurrentBCCSP.example.com"},
		IssuingCertificateURL: []string{"http://crt.example.com/ca1.crt"},

		DNSNames:       []string{"test.example.com"},
		EmailAddresses: []string{"gopher@golang.org"},
		IPAddresses:    []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")},

		PolicyIdentifiers:   []asn1.ObjectIdentifier{[]int{1, 2, 3}},
		PermittedDNSDomains: []string{".example.com", "example.com"},

		CRLDistributionPoints: []string{"http://crl1.example.com/ca1.crl", "http://crl2.example.com/ca1.crl"},

		ExtraExtensions: []pkix.Extension{
			{
				Id:    []int{1, 2, 3, 4},
				Value: extraExtensionData,
			},
		},
	}

	cryptoSigner, err := signer.New(currentBCCSP, k)
	if err != nil {
		t.Fatalf("Failed initializing CyrptoSigner [%s]", err)
	}

	// Export the public key
	pk, err := k.PublicKey()
	if err != nil {
		t.Fatalf("Failed getting ECDSA public key [%s]", err)
	}

	pkRaw, err := pk.Bytes()
	if err != nil {
		t.Fatalf("Failed getting ECDSA raw public key [%s]", err)
	}

	pub, err := utils.DERToPublicKey(pkRaw)
	if err != nil {
		t.Fatalf("Failed converting raw to ECDSA.PublicKey [%s]", err)
	}

	certRaw, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, cryptoSigner)
	if err != nil {
		t.Fatalf("Failed generating self-signed certificate [%s]", err)
	}

	cert, err := utils.DERToX509Certificate(certRaw)
	if err != nil {
		t.Fatalf("Failed generating X509 certificate object from raw [%s]", err)
	}

	// Import the certificate's public key
	pk2, err := currentBCCSP.KeyImport(cert, &bccsp.X509PublicKeyImportOpts{Temporary: false})

	if err != nil {
		t.Fatalf("Failed importing ECDSA public key [%s]", err)
	}
	if pk2 == nil {
		t.Fatal("Failed importing ECDSA public key. Return BCCSP key cannot be nil.")
	}

	// Sign and verify with the imported public key
	msg := []byte("Hello World")

	digest, err := currentBCCSP.Hash(msg, &bccsp.SHAOpts{})
	if err != nil {
		t.Fatalf("Failed computing HASH [%s]", err)
	}

	signature, err := currentBCCSP.Sign(k, digest, nil)
	if err != nil {
		t.Fatalf("Failed generating ECDSA signature [%s]", err)
	}

	valid, err := currentBCCSP.Verify(pk2, signature, digest, nil)
	if err != nil {
		t.Fatalf("Failed verifying ECDSA signature [%s]", err)
	}
	if !valid {
		t.Fatal("Failed verifying ECDSA signature. Signature not valid.")
	}
}

func TestECDSASignatureEncoding(t *testing.T) {
	v := []byte{0x30, 0x07, 0x02, 0x01, 0x8F, 0x02, 0x02, 0xff, 0xf1}
	_, err := asn1.Unmarshal(v, &ecdsaSignature{})
	if err == nil {
		t.Fatalf("Unmarshalling should fail for [% x]", v)
	}
	t.Logf("Unmarshalling correctly failed for [% x] [%s]", v, err)

	v = []byte{0x30, 0x07, 0x02, 0x01, 0x8F, 0x02, 0x02, 0x00, 0x01}
	_, err = asn1.Unmarshal(v, &ecdsaSignature{})
	if err == nil {
		t.Fatalf("Unmarshalling should fail for [% x]", v)
	}
	t.Logf("Unmarshalling correctly failed for [% x] [%s]", v, err)

	v = []byte{0x30, 0x07, 0x02, 0x01, 0x8F, 0x02, 0x81, 0x01, 0x01}
	_, err = asn1.Unmarshal(v, &ecdsaSignature{})
	if err == nil {
		t.Fatalf("Unmarshalling should fail for [% x]", v)
	}
	t.Logf("Unmarshalling correctly failed for [% x] [%s]", v, err)

	v = []byte{0x30, 0x07, 0x02, 0x01, 0x8F, 0x02, 0x81, 0x01, 0x8F}
	_, err = asn1.Unmarshal(v, &ecdsaSignature{})
	if err == nil {
		t.Fatalf("Unmarshalling should fail for [% x]", v)
	}
	t.Logf("Unmarshalling correctly failed for [% x] [%s]", v, err)

	v = []byte{0x30, 0x0A, 0x02, 0x01, 0x8F, 0x02, 0x05, 0x00, 0x00, 0x00, 0x00, 0x8F}
	_, err = asn1.Unmarshal(v, &ecdsaSignature{})
	if err == nil {
		t.Fatalf("Unmarshalling should fail for [% x]", v)
	}
	t.Logf("Unmarshalling correctly failed for [% x] [%s]", v, err)

}

func TestECDSALowS(t *testing.T) {
	// Ensure that signature with low-S are generated
	k, err := currentBCCSP.KeyGen(&bccsp.ECDSAKeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating ECDSA key [%s]", err)
	}

	msg := []byte("Hello World")

	digest, err := currentBCCSP.Hash(msg, &bccsp.SHAOpts{})
	if err != nil {
		t.Fatalf("Failed computing HASH [%s]", err)
	}

	signature, err := currentBCCSP.Sign(k, digest, nil)
	if err != nil {
		t.Fatalf("Failed generating ECDSA signature [%s]", err)
	}

	R, S, err := unmarshalECDSASignature(signature)
	if err != nil {
		t.Fatalf("Failed unmarshalling signature [%s]", err)
	}

	if S.Cmp(curveHalfOrders[k.(*ecdsaPrivateKey).pub.pub.Curve]) >= 0 {
		t.Fatal("Invalid signature. It must have low-S")
	}

	valid, err := currentBCCSP.Verify(k, signature, digest, nil)
	if err != nil {
		t.Fatalf("Failed verifying ECDSA signature [%s]", err)
	}
	if !valid {
		t.Fatal("Failed verifying ECDSA signature. Signature not valid.")
	}

	// Ensure that signature with high-S are rejected.
	for {
		R, S, err = currentBCCSP.(*impl).signP11ECDSA(k.(*ecdsaPrivateKey).keyBlob, digest)
		if err != nil {
			t.Fatalf("Failed generating signature [%s]", err)
		}

		if S.Cmp(curveHalfOrders[k.(*ecdsaPrivateKey).pub.pub.Curve]) > 0 {
			break
		}
	}

	sig, err := marshalECDSASignature(R, S)
	if err != nil {
		t.Fatalf("Failing unmarshalling signature [%s]", err)
	}

	valid, err = currentBCCSP.Verify(k, sig, digest, nil)
	if err == nil {
		t.Fatal("Failed verifying ECDSA signature. It must fail for a signature with high-S")
	}
	if valid {
		t.Fatal("Failed verifying ECDSA signature. It must fail for a signature with high-S")
	}
}

func TestAESKeyGen(t *testing.T) {

	k, err := currentBCCSP.KeyGen(&bccsp.AESKeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating AES_256 key [%s]", err)
	}
	if k == nil {
		t.Fatal("Failed generating AES_256 key. Key must be different from nil")
	}
	if !k.Private() {
		t.Fatal("Failed generating AES_256 key. Key should be private")
	}
	if !k.Symmetric() {
		t.Fatal("Failed generating AES_256 key. Key should be symmetric")
	}

	pk, err := k.PublicKey()
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}
	if pk != nil {
		t.Fatal("Return value should be equal to nil in this case")
	}
}

func TestAESEncrypt(t *testing.T) {

	k, err := currentBCCSP.KeyGen(&bccsp.AESKeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating AES_256 key [%s]", err)
	}

	ct, err := currentBCCSP.Encrypt(k, []byte("Hello World"), &bccsp.AESCBCPKCS7ModeOpts{})
	if err != nil {
		t.Fatalf("Failed encrypting [%s]", err)
	}
	if len(ct) == 0 {
		t.Fatal("Failed encrypting. Nil ciphertext")
	}
}

func TestAESDecrypt(t *testing.T) {

	k, err := currentBCCSP.KeyGen(&bccsp.AESKeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating AES_256 key [%s]", err)
	}

	msg := []byte("Hello World")

	ct, err := currentBCCSP.Encrypt(k, msg, &bccsp.AESCBCPKCS7ModeOpts{})
	if err != nil {
		t.Fatalf("Failed encrypting [%s]", err)
	}

	pt, err := currentBCCSP.Decrypt(k, ct, bccsp.AESCBCPKCS7ModeOpts{})
	if err != nil {
		t.Fatalf("Failed decrypting [%s]", err)
	}
	if len(ct) == 0 {
		t.Fatal("Failed decrypting. Nil plaintext")
	}

	if !bytes.Equal(msg, pt) {
		t.Fatalf("Failed decrypting. Decrypted plaintext is different from the original. [%x][%x]", msg, pt)
	}
}

func TestKeyDerivNilKey(t *testing.T) {
	_, err := currentBCCSP.KeyDeriv(nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid Key. It must not be nil.")
}

func TestHMACTruncated256KeyDerivOverAES256Key(t *testing.T) {

	k, err := currentBCCSP.KeyGen(&bccsp.AESKeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating AES_256 key [%s]", err)
	}

	hmcaedKey, err := currentBCCSP.KeyDeriv(k, &bccsp.HMACTruncated256AESDeriveKeyOpts{Temporary: false, Arg: []byte{1}})
	if err != nil {
		t.Fatalf("Failed HMACing AES_256 key [%s]", err)
	}
	if k == nil {
		t.Fatal("Failed HMACing AES_256 key. HMACed Key must be different from nil")
	}
	if !hmcaedKey.Private() {
		t.Fatal("Failed HMACing AES_256 key. HMACed Key should be private")
	}
	if !hmcaedKey.Symmetric() {
		t.Fatal("Failed HMACing AES_256 key. HMACed Key should be asymmetric")
	}
	raw, err := hmcaedKey.Bytes()
	if err == nil {
		t.Fatal("Failed marshalling to bytes. Operation must be forbidden")
	}
	if len(raw) != 0 {
		t.Fatal("Failed marshalling to bytes. Operation must return 0 bytes")
	}

	msg := []byte("Hello World")

	ct, err := currentBCCSP.Encrypt(hmcaedKey, msg, &bccsp.AESCBCPKCS7ModeOpts{})
	if err != nil {
		t.Fatalf("Failed encrypting [%s]", err)
	}

	pt, err := currentBCCSP.Decrypt(hmcaedKey, ct, bccsp.AESCBCPKCS7ModeOpts{})
	if err != nil {
		t.Fatalf("Failed decrypting [%s]", err)
	}
	if len(ct) == 0 {
		t.Fatal("Failed decrypting. Nil plaintext")
	}

	if !bytes.Equal(msg, pt) {
		t.Fatalf("Failed decrypting. Decrypted plaintext is different from the original. [%x][%x]", msg, pt)
	}

}

func TestHMACKeyDerivOverAES256Key(t *testing.T) {

	k, err := currentBCCSP.KeyGen(&bccsp.AESKeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating AES_256 key [%s]", err)
	}

	hmcaedKey, err := currentBCCSP.KeyDeriv(k, &bccsp.HMACDeriveKeyOpts{Temporary: false, Arg: []byte{1}})

	if err != nil {
		t.Fatalf("Failed HMACing AES_256 key [%s]", err)
	}
	if k == nil {
		t.Fatal("Failed HMACing AES_256 key. HMACed Key must be different from nil")
	}
	if !hmcaedKey.Private() {
		t.Fatal("Failed HMACing AES_256 key. HMACed Key should be private")
	}
	if !hmcaedKey.Symmetric() {
		t.Fatal("Failed HMACing AES_256 key. HMACed Key should be asymmetric")
	}
	raw, err := hmcaedKey.Bytes()
	if err != nil {
		t.Fatalf("Failed marshalling to bytes [%s]", err)
	}
	if len(raw) == 0 {
		t.Fatal("Failed marshalling to bytes. 0 bytes")
	}
}

func TestAES256KeyImport(t *testing.T) {
	t.SkipNow()
	raw, err := sw.GetRandomBytes(32)
	if err != nil {
		t.Fatalf("Failed generating AES key [%s]", err)
	}

	k, err := currentBCCSP.KeyImport(raw, &bccsp.AES256ImportKeyOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed importing AES_256 key [%s]", err)
	}
	if k == nil {
		t.Fatal("Failed importing AES_256 key. Imported Key must be different from nil")
	}
	if !k.Private() {
		t.Fatal("Failed HMACing AES_256 key. Imported Key should be private")
	}
	if !k.Symmetric() {
		t.Fatal("Failed HMACing AES_256 key. Imported Key should be asymmetric")
	}
	raw, err = k.Bytes()
	if err == nil {
		t.Fatal("Failed marshalling to bytes. Marshalling must fail.")
	}
	if len(raw) != 0 {
		t.Fatal("Failed marshalling to bytes. Output should be 0 bytes")
	}

	msg := []byte("Hello World")

	ct, err := currentBCCSP.Encrypt(k, msg, &bccsp.AESCBCPKCS7ModeOpts{})
	if err != nil {
		t.Fatalf("Failed encrypting [%s]", err)
	}

	pt, err := currentBCCSP.Decrypt(k, ct, bccsp.AESCBCPKCS7ModeOpts{})
	if err != nil {
		t.Fatalf("Failed decrypting [%s]", err)
	}
	if len(ct) == 0 {
		t.Fatal("Failed decrypting. Nil plaintext")
	}

	if !bytes.Equal(msg, pt) {
		t.Fatalf("Failed decrypting. Decrypted plaintext is different from the original. [%x][%x]", msg, pt)
	}
}

func TestAES256KeyImportBadPaths(t *testing.T) {

	_, err := currentBCCSP.KeyImport(nil, &bccsp.AES256ImportKeyOpts{Temporary: false})
	if err == nil {
		t.Fatal("Failed importing key. Must fail on importing nil key")
	}

	_, err = currentBCCSP.KeyImport([]byte{1}, &bccsp.AES256ImportKeyOpts{Temporary: false})
	if err == nil {
		t.Fatal("Failed importing key. Must fail on importing a key with an invalid length")
	}
}

func TestAES256KeyGenSKI(t *testing.T) {

	k, err := currentBCCSP.KeyGen(&bccsp.AESKeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating AES_256 key [%s]", err)
	}

	k2, err := currentBCCSP.GetKey(k.SKI())
	if err != nil {
		t.Fatalf("Failed getting AES_256 key [%s]", err)
	}
	if k2 == nil {
		t.Fatal("Failed getting AES_256 key. Key must be different from nil")
	}
	if !k2.Private() {
		t.Fatal("Failed getting AES_256 key. Key should be private")
	}
	if !k2.Symmetric() {
		t.Fatal("Failed getting AES_256 key. Key should be symmetric")
	}

	// Check that the SKIs are the same
	if !bytes.Equal(k.SKI(), k2.SKI()) {
		t.Fatalf("SKIs are different [%x]!=[%x]", k.SKI(), k2.SKI())
	}

}

func TestSHA(t *testing.T) {

	for i := 0; i < 100; i++ {
		b, err := sw.GetRandomBytes(i)
		if err != nil {
			t.Fatalf("Failed getting random bytes [%s]", err)
		}

		h1, err := currentBCCSP.Hash(b, &bccsp.SHAOpts{})
		if err != nil {
			t.Fatalf("Failed computing SHA [%s]", err)
		}

		var h hash.Hash
		switch currentTestConfig.hashFamily {
		case "SHA2":
			switch currentTestConfig.securityLevel {
			case 256:
				h = sha256.New()
			case 384:
				h = sha512.New384()
			default:
				t.Fatalf("Invalid security level [%d]", currentTestConfig.securityLevel)
			}
		case "SHA3":
			switch currentTestConfig.securityLevel {
			case 256:
				h = sha3.New256()
			case 384:
				h = sha3.New384()
			default:
				t.Fatalf("Invalid security level [%d]", currentTestConfig.securityLevel)
			}
		default:
			t.Fatalf("Invalid hash family [%s]", currentTestConfig.hashFamily)
		}

		h.Write(b)
		h2 := h.Sum(nil)
		if !bytes.Equal(h1, h2) {
			t.Fatalf("Discrempancy found in HASH result [%x], [%x]!=[%x]", b, h1, h2)
		}
	}
}

func TestRSAKeyGenEphemeral(t *testing.T) {
	k, err := currentBCCSP.KeyGen(&bccsp.RSAKeyGenOpts{Temporary: true})
	if err != nil {
		t.Fatalf("Failed generating RSA key [%s]", err)
	}
	if k == nil {
		t.Fatal("Failed generating RSA key. Key must be different from nil")
	}
	if !k.Private() {
		t.Fatal("Failed generating RSA key. Key should be private")
	}
	if k.Symmetric() {
		t.Fatal("Failed generating RSA key. Key should be asymmetric")
	}

	pk, err := k.PublicKey()
	if err != nil {
		t.Fatalf("Failed generating RSA corresponding public key [%s]", err)
	}
	if pk == nil {
		t.Fatal("PK must be different from nil")
	}

	b, err := k.Bytes()
	if err == nil {
		t.Fatal("Secret keys cannot be exported. It must fail in this case")
	}
	if len(b) != 0 {
		t.Fatal("Secret keys cannot be exported. It must be nil")
	}

}

func TestRSAPrivateKeySKI(t *testing.T) {

	k, err := currentBCCSP.KeyGen(&bccsp.RSAKeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating RSA key [%s]", err)
	}

	ski := k.SKI()
	if len(ski) == 0 {
		t.Fatal("SKI not valid. Zero length.")
	}
}

func TestRSAKeyGenNonEphemeral(t *testing.T) {

	k, err := currentBCCSP.KeyGen(&bccsp.RSAKeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating RSA key [%s]", err)
	}
	if k == nil {
		t.Fatal("Failed generating RSA key. Key must be different from nil")
	}
	if !k.Private() {
		t.Fatal("Failed generating RSA key. Key should be private")
	}
	if k.Symmetric() {
		t.Fatal("Failed generating RSA key. Key should be asymmetric")
	}
}

func TestRSAGetKeyBySKI(t *testing.T) {

	k, err := currentBCCSP.KeyGen(&bccsp.RSAKeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating RSA key [%s]", err)
	}

	k2, err := currentBCCSP.GetKey(k.SKI())
	if err != nil {
		t.Fatalf("Failed getting RSA key [%s]", err)
	}
	if k2 == nil {
		t.Fatal("Failed getting RSA key. Key must be different from nil")
	}
	if !k2.Private() {
		t.Fatal("Failed getting RSA key. Key should be private")
	}
	if k2.Symmetric() {
		t.Fatal("Failed getting RSA key. Key should be asymmetric")
	}

	// Check that the SKIs are the same
	if !bytes.Equal(k.SKI(), k2.SKI()) {
		t.Fatalf("SKIs are different [%x]!=[%x]", k.SKI(), k2.SKI())
	}
}

func TestRSAPublicKeyFromPrivateKey(t *testing.T) {

	k, err := currentBCCSP.KeyGen(&bccsp.RSAKeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating RSA key [%s]", err)
	}

	pk, err := k.PublicKey()
	if err != nil {
		t.Fatalf("Failed getting public key from private RSA key [%s]", err)
	}
	if pk == nil {
		t.Fatal("Failed getting public key from private RSA key. Key must be different from nil")
	}
	if pk.Private() {
		t.Fatal("Failed generating RSA key. Key should be public")
	}
	if pk.Symmetric() {
		t.Fatal("Failed generating RSA key. Key should be asymmetric")
	}
}

func TestRSAPublicKeyBytes(t *testing.T) {

	k, err := currentBCCSP.KeyGen(&bccsp.RSAKeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating RSA key [%s]", err)
	}

	pk, err := k.PublicKey()
	if err != nil {
		t.Fatalf("Failed getting public key from private RSA key [%s]", err)
	}

	raw, err := pk.Bytes()
	if err != nil {
		t.Fatalf("Failed marshalling RSA public key [%s]", err)
	}
	if len(raw) == 0 {
		t.Fatal("Failed marshalling RSA public key. Zero length")
	}
}

func TestRSAPublicKeySKI(t *testing.T) {

	k, err := currentBCCSP.KeyGen(&bccsp.RSAKeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating RSA key [%s]", err)
	}

	pk, err := k.PublicKey()
	if err != nil {
		t.Fatalf("Failed getting public key from private RSA key [%s]", err)
	}

	ski := pk.SKI()
	if len(ski) == 0 {
		t.Fatal("SKI not valid. Zero length.")
	}
}

func TestRSASign(t *testing.T) {

	k, err := currentBCCSP.KeyGen(&bccsp.RSAKeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating RSA key [%s]", err)
	}

	msg := []byte("Hello World")

	digest, err := currentBCCSP.Hash(msg, &bccsp.SHAOpts{})
	if err != nil {
		t.Fatalf("Failed computing HASH [%s]", err)
	}

	signature, err := currentBCCSP.Sign(k, digest, &rsa.PSSOptions{SaltLength: 32, Hash: getCryptoHashIndex(t)})
	if err != nil {
		t.Fatalf("Failed generating RSA signature [%s]", err)
	}
	if len(signature) == 0 {
		t.Fatal("Failed generating RSA key. Signature must be different from nil")
	}
}

func TestRSAVerify(t *testing.T) {

	k, err := currentBCCSP.KeyGen(&bccsp.RSAKeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating RSA key [%s]", err)
	}

	msg := []byte("Hello World")

	digest, err := currentBCCSP.Hash(msg, &bccsp.SHAOpts{})
	if err != nil {
		t.Fatalf("Failed computing HASH [%s]", err)
	}

	signature, err := currentBCCSP.Sign(k, digest, &rsa.PSSOptions{SaltLength: 32, Hash: getCryptoHashIndex(t)})
	if err != nil {
		t.Fatalf("Failed generating RSA signature [%s]", err)
	}

	valid, err := currentBCCSP.Verify(k, signature, digest, &rsa.PSSOptions{SaltLength: 32, Hash: getCryptoHashIndex(t)})
	if err != nil {
		t.Fatalf("Failed verifying RSA signature [%s]", err)
	}
	if !valid {
		t.Fatal("Failed verifying RSA signature. Signature not valid.")
	}

	pk, err := k.PublicKey()
	if err != nil {
		t.Fatalf("Failed getting corresponding public key [%s]", err)
	}

	valid, err = currentBCCSP.Verify(pk, signature, digest, &rsa.PSSOptions{SaltLength: 32, Hash: getCryptoHashIndex(t)})
	if err != nil {
		t.Fatalf("Failed verifying RSA signature [%s]", err)
	}
	if !valid {
		t.Fatal("Failed verifying RSA signature. Signature not valid.")
	}

	// Store public key
	err = currentKS.StoreKey(pk)
	if err != nil {
		t.Fatalf("Failed storing corresponding public key [%s]", err)
	}

	pk2, err := currentKS.GetKey(pk.SKI())
	if err != nil {
		t.Fatalf("Failed retrieving corresponding public key [%s]", err)
	}

	valid, err = currentBCCSP.Verify(pk2, signature, digest, &rsa.PSSOptions{SaltLength: 32, Hash: getCryptoHashIndex(t)})
	if err != nil {
		t.Fatalf("Failed verifying RSA signature [%s]", err)
	}
	if !valid {
		t.Fatal("Failed verifying RSA signature. Signature not valid.")
	}

}

func TestRSAKeyImportFromRSAPublicKey(t *testing.T) {

	// Generate an RSA key
	k, err := currentBCCSP.KeyGen(&bccsp.RSAKeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating RSA key [%s]", err)
	}

	// Export the public key
	pk, err := k.PublicKey()
	if err != nil {
		t.Fatalf("Failed getting RSA public key [%s]", err)
	}

	pkRaw, err := pk.Bytes()
	if err != nil {
		t.Fatalf("Failed getting RSA raw public key [%s]", err)
	}

	pub, err := utils.DERToPublicKey(pkRaw)
	if err != nil {
		t.Fatalf("Failed converting raw to RSA.PublicKey [%s]", err)
	}

	// Import the RSA.PublicKey
	pk2, err := currentBCCSP.KeyImport(pub, &bccsp.RSAGoPublicKeyImportOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed importing RSA public key [%s]", err)
	}
	if pk2 == nil {
		t.Fatal("Failed importing RSA public key. Return BCCSP key cannot be nil.")
	}

	// Sign and verify with the imported public key
	msg := []byte("Hello World")

	digest, err := currentBCCSP.Hash(msg, &bccsp.SHAOpts{})
	if err != nil {
		t.Fatalf("Failed computing HASH [%s]", err)
	}

	signature, err := currentBCCSP.Sign(k, digest, &rsa.PSSOptions{SaltLength: 32, Hash: getCryptoHashIndex(t)})
	if err != nil {
		t.Fatalf("Failed generating RSA signature [%s]", err)
	}

	valid, err := currentBCCSP.Verify(pk2, signature, digest, &rsa.PSSOptions{SaltLength: 32, Hash: getCryptoHashIndex(t)})
	if err != nil {
		t.Fatalf("Failed verifying RSA signature [%s]", err)
	}
	if !valid {
		t.Fatal("Failed verifying RSA signature. Signature not valid.")
	}
}

func TestKeyImportFromX509RSAPublicKey(t *testing.T) {

	// Generate an RSA key
	k, err := currentBCCSP.KeyGen(&bccsp.RSAKeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating RSA key [%s]", err)
	}

	// Generate a self-signed certificate
	testExtKeyUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	testUnknownExtKeyUsage := []asn1.ObjectIdentifier{[]int{1, 2, 3}, []int{2, 59, 1}}
	extraExtensionData := []byte("extra extension")
	commonName := "test.example.com"
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Σ Acme Co"},
			Country:      []string{"US"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  []int{2, 5, 4, 42},
					Value: "Gopher",
				},
				// This should override the Country, above.
				{
					Type:  []int{2, 5, 4, 6},
					Value: "NL",
				},
			},
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(1 * time.Hour),

		SignatureAlgorithm: x509.SHA256WithRSA,

		SubjectKeyId: []byte{1, 2, 3, 4},
		KeyUsage:     x509.KeyUsageCertSign,

		ExtKeyUsage:        testExtKeyUsage,
		UnknownExtKeyUsage: testUnknownExtKeyUsage,

		BasicConstraintsValid: true,
		IsCA: true,

		OCSPServer:            []string{"http://ocurrentBCCSP.example.com"},
		IssuingCertificateURL: []string{"http://crt.example.com/ca1.crt"},

		DNSNames:       []string{"test.example.com"},
		EmailAddresses: []string{"gopher@golang.org"},
		IPAddresses:    []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")},

		PolicyIdentifiers:   []asn1.ObjectIdentifier{[]int{1, 2, 3}},
		PermittedDNSDomains: []string{".example.com", "example.com"},

		CRLDistributionPoints: []string{"http://crl1.example.com/ca1.crl", "http://crl2.example.com/ca1.crl"},

		ExtraExtensions: []pkix.Extension{
			{
				Id:    []int{1, 2, 3, 4},
				Value: extraExtensionData,
			},
		},
	}

	cryptoSigner, err := signer.New(currentBCCSP, k)
	if err != nil {
		t.Fatalf("Failed initializing CyrptoSigner [%s]", err)
	}

	// Export the public key
	pk, err := k.PublicKey()
	if err != nil {
		t.Fatalf("Failed getting RSA public key [%s]", err)
	}

	pkRaw, err := pk.Bytes()
	if err != nil {
		t.Fatalf("Failed getting RSA raw public key [%s]", err)
	}

	pub, err := utils.DERToPublicKey(pkRaw)
	if err != nil {
		t.Fatalf("Failed converting raw to RSA.PublicKey [%s]", err)
	}

	certRaw, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, cryptoSigner)
	if err != nil {
		t.Fatalf("Failed generating self-signed certificate [%s]", err)
	}

	cert, err := utils.DERToX509Certificate(certRaw)
	if err != nil {
		t.Fatalf("Failed generating X509 certificate object from raw [%s]", err)
	}

	// Import the certificate's public key
	pk2, err := currentBCCSP.KeyImport(cert, &bccsp.X509PublicKeyImportOpts{Temporary: false})

	if err != nil {
		t.Fatalf("Failed importing RSA public key [%s]", err)
	}
	if pk2 == nil {
		t.Fatal("Failed importing RSA public key. Return BCCSP key cannot be nil.")
	}

	// Sign and verify with the imported public key
	msg := []byte("Hello World")

	digest, err := currentBCCSP.Hash(msg, &bccsp.SHAOpts{})
	if err != nil {
		t.Fatalf("Failed computing HASH [%s]", err)
	}

	signature, err := currentBCCSP.Sign(k, digest, &rsa.PSSOptions{SaltLength: 32, Hash: getCryptoHashIndex(t)})
	if err != nil {
		t.Fatalf("Failed generating RSA signature [%s]", err)
	}

	valid, err := currentBCCSP.Verify(pk2, signature, digest, &rsa.PSSOptions{SaltLength: 32, Hash: getCryptoHashIndex(t)})
	if err != nil {
		t.Fatalf("Failed verifying RSA signature [%s]", err)
	}
	if !valid {
		t.Fatal("Failed verifying RSA signature. Signature not valid.")
	}
}

func getCryptoHashIndex(t *testing.T) crypto.Hash {
	switch currentTestConfig.hashFamily {
	case "SHA2":
		switch currentTestConfig.securityLevel {
		case 256:
			return crypto.SHA256
		case 384:
			return crypto.SHA384
		default:
			t.Fatalf("Invalid security level [%d]", currentTestConfig.securityLevel)
		}
	case "SHA3":
		switch currentTestConfig.securityLevel {
		case 256:
			return crypto.SHA3_256
		case 384:
			return crypto.SHA3_384
		default:
			t.Fatalf("Invalid security level [%d]", currentTestConfig.securityLevel)
		}
	default:
		t.Fatalf("Invalid hash family [%s]", currentTestConfig.hashFamily)
	}

	return crypto.SHA3_256
}
