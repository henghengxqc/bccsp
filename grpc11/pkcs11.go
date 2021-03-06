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
package grpc11

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"

	"golang.org/x/net/context"

	pb "github.com/hyperledger/fabric/bccsp/grpc11/protos"
)

// Look for an EC key by SKI, stored in CKA_ID
// This function can probably be addapted for both EC and RSA keys.
func (csp *impl) getECKey(ski []byte) (pubKey *ecdsa.PublicKey, isPriv bool, err error) {
	k, err := csp.grpc.GetECKey(context.Background(), &pb.GetKeyInfo{ski})
	if err != nil {
		return nil, false, fmt.Errorf("Could not remote-load PKCS11 library [%s]\n Remote Response: <%+v>", err, k)
	}
	if k.Error != "" {
		return nil, false, fmt.Errorf("Remote Load call reports error: %s", k.Error)
	}

	curveOid := new(asn1.ObjectIdentifier)
	_, err = asn1.Unmarshal(k.Oid, curveOid)
	if err != nil {
		return nil, false, fmt.Errorf("Failed Unmarshaling Curve OID [%s]\n%s", err.Error(), hex.EncodeToString(k.Oid))
	}

	curve := namedCurveFromOID(*curveOid)
	if curve == nil {
		return nil, false, fmt.Errorf("Cound not recognize Curve from OID")
	}
	x, y := elliptic.Unmarshal(curve, k.PubKey)
	if x == nil {
		return nil, false, fmt.Errorf("Failed Unmarshaling Public Key")
	}

	pubKey = &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
	return pubKey, k.IsPriv, nil
}

// RFC 5480, 2.1.1.1. Named Curve
//
// secp224r1 OBJECT IDENTIFIER ::= {
//   iso(1) identified-organization(3) certicom(132) curve(0) 33 }
//
// secp256r1 OBJECT IDENTIFIER ::= {
//   iso(1) member-body(2) us(840) ansi-X9-62(10045) curves(3)
//   prime(1) 7 }
//
// secp384r1 OBJECT IDENTIFIER ::= {
//   iso(1) identified-organization(3) certicom(132) curve(0) 34 }
//
// secp521r1 OBJECT IDENTIFIER ::= {
//   iso(1) identified-organization(3) certicom(132) curve(0) 35 }
//
var (
	oidNamedCurveP224 = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	oidNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidNamedCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
)

func namedCurveFromOID(oid asn1.ObjectIdentifier) elliptic.Curve {
	switch {
	case oid.Equal(oidNamedCurveP224):
		return elliptic.P224()
	case oid.Equal(oidNamedCurveP256):
		return elliptic.P256()
	case oid.Equal(oidNamedCurveP384):
		return elliptic.P384()
	case oid.Equal(oidNamedCurveP521):
		return elliptic.P521()
	}
	return nil
}

func oidFromNamedCurve(curve elliptic.Curve) (asn1.ObjectIdentifier, bool) {
	switch curve {
	case elliptic.P224():
		return oidNamedCurveP224, true
	case elliptic.P256():
		return oidNamedCurveP256, true
	case elliptic.P384():
		return oidNamedCurveP384, true
	case elliptic.P521():
		return oidNamedCurveP521, true
	}

	return nil, false
}

func (csp *impl) generateECKey(curve asn1.ObjectIdentifier, ephemeral bool) ([]byte, *ecdsa.PublicKey, error) {
	marshaledOID, err := asn1.Marshal(curve)
	if err != nil {
		return nil, nil, fmt.Errorf("Could not marshal OID [%s]", err.Error())
	}

	k, err := csp.grpc.GenerateECKey(context.Background(), &pb.GenerateInfo{marshaledOID, ephemeral})
	if err != nil {
		return nil, nil, fmt.Errorf("Could not remote-generate PKCS11 library [%s]\n Remote Response: <%+v>", err, k)
	}
	if k.Error != "" {
		return nil, nil, fmt.Errorf("Remote Generate call reports error: %s", k.Error)
	}

	nistCurve := namedCurveFromOID(curve)
	if curve == nil {
		return nil, nil, fmt.Errorf("Cound not recognize Curve from OID")
	}
	x, y := elliptic.Unmarshal(nistCurve, k.PubKey)
	if x == nil {
		return nil, nil, fmt.Errorf("Failed Unmarshaling Public Key")
	}

	pubGoKey := &ecdsa.PublicKey{Curve: nistCurve, X: x, Y: y}
	return k.Ski, pubGoKey, nil
}

func (csp *impl) signP11ECDSA(ski []byte, msg []byte) (R, S *big.Int, err error) {
	sig, err := csp.grpc.SignP11ECDSA(context.Background(), &pb.SignInfo{ski, msg})
	if err != nil {
		return nil, nil, fmt.Errorf("Could not remote-sign PKCS11 library [%s]\n Remote Response: <%s>", err, sig)
	}
	if sig.Error != "" {
		return nil, nil, fmt.Errorf("Remote Sign call reports error: %s", sig.Error)
	}

	R = new(big.Int)
	S = new(big.Int)
	R.SetBytes(sig.Sig[0 : len(sig.Sig)/2])
	S.SetBytes(sig.Sig[len(sig.Sig)/2:])

	return R, S, nil
}

func (csp *impl) verifyP11ECDSA(ski []byte, msg []byte, R, S *big.Int, byteSize int) (valid bool, err error) {
	r := R.Bytes()
	s := S.Bytes()

	// Pad front of R and S with Zeroes if needed
	sig := make([]byte, 2*byteSize)
	copy(sig[byteSize-len(r):byteSize], r)
	copy(sig[2*byteSize-len(s):], s)

	val, err := csp.grpc.VerifyP11ECDSA(context.Background(), &pb.VerifyInfo{ski, msg, sig})
	if err != nil {
		return false, fmt.Errorf("Could not remote-verify PKCS11 library [%s]\n Remote Response: <%+v>", err, val)
	}
	if val.Error != "" {
		return false, fmt.Errorf("Remote Verify call reports error: %s", val.Error)
	}

	return val.Valid, nil
}

const (
	privateKeyFlag = true
	publicKeyFlag  = false
)

func (csp *impl) importECKey(curve asn1.ObjectIdentifier, privKey, ecPt []byte, ephemeral bool, keyType bool) (ski []byte, err error) {
	marshaledOID, err := asn1.Marshal(curve)
	if err != nil {
		return nil, fmt.Errorf("Could not marshal OID [%s]", err.Error())
	}

	k, err := csp.grpc.ImportECKey(context.Background(), &pb.ImportInfo{marshaledOID, privKey, ecPt, ephemeral, keyType})
	if err != nil {
		return nil, fmt.Errorf("Could not remote-import PKCS11 library [%s]\n Remote Response: <%s>", err, k)
	}
	if k.Error != "" {
		return nil, fmt.Errorf("Remote ImportKey call reports error: %s", k.Error)
	}
	return k.Ski, nil
}

func (csp *impl) getSecretValue(ski []byte) []byte {
	return nil
}
