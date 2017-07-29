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

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"os"
	"testing"

	"golang.org/x/net/context"
	"google.golang.org/grpc"

	pb "github.com/hyperledger/fabric/bccsp/grep11/protos"
)

var (
	Address = "localhost"
	Port    = "6789"
)

func genPin() ([]byte, error) {
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

func getNonce() ([]byte, error) {
	const nonceLen = 1024
	nonce := make([]byte, nonceLen)
	_, err := rand.Read(nonce)
	if err != nil {
		return nil, fmt.Errorf("Failed on rand.Read() in getNonce [%s]", err)
	}
	return nonce, nil
}

func TestMain(m *testing.M) {
	CreateTestServer()

	ret := m.Run()
	if ret != 0 {
		fmt.Printf("Failed testing [%d]", ret)
		os.Exit(-1)
	}
}

func TestManagerLoad(t *testing.T) {
	conn, err := grpc.Dial(Address+":"+Port, grpc.WithInsecure())
	if err != nil {
		t.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := pb.NewGrep11ManagerClient(conn)

	pin, err := genPin()
	if err != nil {
		t.Fatalf("Could not generate pin %s", err)
	}
	nonce, err := getNonce()
	if err != nil {
		t.Fatalf("Could not generate nonce %s", err)
	}

	r, err := c.Load(context.Background(), &pb.LoadInfo{pin, nonce})
	if err != nil {
		t.Fatalf("could not greet: %v", err)
	}
	t.Logf("Greeting from %s", r.Address)
}

func TestServerConnect(t *testing.T) {
	conn, err := grpc.Dial(Address+":"+Port, grpc.WithInsecure())
	if err != nil {
		t.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := pb.NewGrep11ManagerClient(conn)

	pin, err := genPin()
	if err != nil {
		t.Fatalf("Could not generate pin %s", err)
	}
	nonce, err := getNonce()
	if err != nil {
		t.Fatalf("Could not generate nonce %s", err)
	}

	r, err := c.Load(context.Background(), &pb.LoadInfo{pin, nonce})
	if err != nil {
		t.Fatalf("could not greet: %v", err)
	}

	conn, err = grpc.Dial(r.Address, grpc.WithInsecure())
	if err != nil {
		t.Fatalf("did not connect: %v", err)
	}
	t.Logf("Coonected to %s", r.Address)
	defer conn.Close()
}

func TestServerSignVerify(t *testing.T) {
	conn, err := grpc.Dial(Address+":"+Port, grpc.WithInsecure())
	if err != nil {
		t.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	m := pb.NewGrep11ManagerClient(conn)

	pin, err := genPin()
	if err != nil {
		t.Fatalf("Could not generate pin %s", err)
	}
	nonce, err := getNonce()
	if err != nil {
		t.Fatalf("Could not generate nonce %s", err)
	}

	r, err := m.Load(context.Background(), &pb.LoadInfo{pin, nonce})
	if err != nil {
		t.Fatalf("could not greet: %v", err)
	}

	conn, err = grpc.Dial(r.Address, grpc.WithInsecure())
	if err != nil {
		t.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	t.Logf("Coonected to %s", r.Address)

	s := pb.NewGrep11Client(conn)

	oidNamedCurveP256 := asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	marshaledOID, err := asn1.Marshal(oidNamedCurveP256)
	if err != nil {
		t.Fatalf("Could not marshal OID [%s]", err.Error())
	}
	k, err := s.GenerateECKey(context.Background(), &pb.GenerateInfo{marshaledOID})
	if err != nil {
		t.Fatalf("Failed generating ECDSA key [%s]", err)
	}
	if k.Error != "" {
		t.Fatalf("Server returned error [%s]", k.Error)
	}

	msg := []byte("Hello World")
	digest := sha256.Sum256(msg)

	signature, err := s.SignP11ECDSA(context.Background(), &pb.SignInfo{k.PrivKey, digest[:]})
	if err != nil {
		t.Fatalf("Failed generating ECDSA signature [%s]", err)
	}
	if signature.Error != "" {
		t.Fatalf("Server returned error [%s]", signature.Error)
	}
	if len(signature.Sig) == 0 {
		t.Fatal("Failed generating ECDSA key. Signature must be different from nil")
	}

	verify, err := s.VerifyP11ECDSA(context.Background(), &pb.VerifyInfo{k.PubKey, digest[:], signature.Sig})
	if err != nil {
		t.Fatalf("Failed verifying ECDSA signature [%s]", err)
	}
	if verify.Error != "" {
		t.Fatalf("Server returned error [%s]", verify.Error)
	}
	if !verify.Valid {
		t.Fatal("Failed verifying ECDSA signature. Signature not valid.")
	}

}
