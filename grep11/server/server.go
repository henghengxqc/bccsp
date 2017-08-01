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
#cgo LDFLAGS: -l:libep11.a
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

CK_RV generateKeyPair (
                      const unsigned char *pinblob,       size_t pinbloblen,
                            unsigned char *key,       size_t *klen,
                            unsigned char *pubkey,    size_t *pklen);

CK_RV signSingle (const unsigned char *key,      size_t klen,
                              CK_BYTE_PTR hash,    CK_ULONG hlen,
                              CK_BYTE_PTR sig, CK_ULONG_PTR slen);

CK_RV verifySingle (const unsigned char *key,      size_t klen,
                              CK_BYTE_PTR hash,    CK_ULONG hlen,
                              CK_BYTE_PTR sig,     CK_ULONG slen);
*/
import "C"

import (
	"fmt"
	"net"
	"time"
	"unsafe"

	"github.com/op/go-logging"
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"github.com/hyperledger/fabric/common/flogging"
	pb "github.com/vpaprots/bccsp/grep11/protos"
)

var (
	logger = flogging.MustGetLogger("grep11server")
)

func init() {
	C.m_init()
}

func Start(address, port, store string) {
	cleanKnownSessions(store)

	m := &grep11Manager{address, port, store}

	lis, err := net.Listen("tcp", m.address+":"+m.port)
	if err != nil {
		logger.Fatalf("failed to listen: %v", err)
	}
	logger.Infof("Manager listening on %s", lis.Addr().String())
	grpcManager := grpc.NewServer()
	pb.RegisterGrep11ManagerServer(grpcManager, m)
	grpcManager.Serve(lis)
}

type grep11Manager struct {
	address string
	port    string
	store   string
}

func (m *grep11Manager) Load(c context.Context, loadInfo *pb.LoadInfo) (*pb.LoadStatus, error) {
	rc := &pb.LoadStatus{}
	server := &grep11Server{}

	rv := C.login((*C.CK_UTF8CHAR)(unsafe.Pointer(&loadInfo.Pin[0])), C.CK_ULONG(len(loadInfo.Pin)),
		(*C.uchar)(unsafe.Pointer(&loadInfo.Nonce[0])), C.size_t(len(loadInfo.Nonce)),
		(*C.uchar)(unsafe.Pointer(&server.pinblob[0])), (*C.size_t)(unsafe.Pointer(&server.pinbloblen)))
	if rv != C.CKR_OK {
		logger.Errorf("m_Login returned 0x%x\n", rv)
		rc.Error = fmt.Sprintf("m_Login returned 0x%x\n", rv)
		return rc, fmt.Errorf("m_Login returned 0x%x\n", rv)
	}

	err := logSession(m.store, server.pinblob[:server.pinbloblen])
	if err != nil {
		logger.Warningf("Error recording pin %s [%s]", loadInfo.Pin, err)
	}

	lis, err := net.Listen("tcp", m.address+":0")
	if err != nil {
		rc.Error = fmt.Sprintf("Failed to Listen: %v", err)
		rc.Address = ""
		return rc, fmt.Errorf(rc.Error)
	}
	grpcServer := grpc.NewServer()
	pb.RegisterGrep11Server(grpcServer, server)
	go grpcServer.Serve(lis)

	rc.Error = ""
	rc.Address = lis.Addr().String()
	server.logger = flogging.MustGetLogger("grep11server_" + rc.Address)

	logger.Infof("Listening on %s for pin %s", rc.Address, loadInfo.Pin)

	return rc, err
}

type grep11Server struct {
	pinblob    [1024]byte
	pinbloblen int
	logger     *logging.Logger
}

func (s *grep11Server) GenerateECKey(c context.Context, generateInfo *pb.GenerateInfo) (*pb.GenerateStatus, error) {
	rc := &pb.GenerateStatus{}
	var keylen int = 1024
	var pubkeylen int = 1024
	keyblob := make([]byte, keylen)
	pubkeyblob := make([]byte, pubkeylen)

	rv := C.generateKeyPair((*C.uchar)(unsafe.Pointer(&s.pinblob[0])), C.size_t(s.pinbloblen),
		(*C.uchar)(unsafe.Pointer(&keyblob[0])), (*C.size_t)(unsafe.Pointer(&keylen)),
		(*C.uchar)(unsafe.Pointer(&pubkeyblob[0])), (*C.size_t)(unsafe.Pointer(&pubkeylen)))
	if rv != C.CKR_OK {
		logger.Errorf("m_GenerateKeyPair returned 0x%x\n", rv)
		rc.Error = fmt.Sprintf("m_GenerateKeyPair returned 0x%x\n", rv)
		return rc, fmt.Errorf("m_GenerateKeyPair returned 0x%x\n", rv)
	}

	rc.PrivKey = keyblob[:keylen]
	rc.PubKey = pubkeyblob[:pubkeylen]
	rc.Error = ""
	return rc, nil
}

func (s *grep11Server) SignP11ECDSA(c context.Context, signInfo *pb.SignInfo) (*pb.SignStatus, error) {
	rc := &pb.SignStatus{}

	var siglen int = 1024
	sig := make([]byte, siglen)

	rv := C.signSingle((*C.uchar)(unsafe.Pointer(&signInfo.PrivKey[0])), C.size_t(len(signInfo.PrivKey)),
		C.CK_BYTE_PTR(unsafe.Pointer(&signInfo.Hash[0])), C.CK_ULONG(len(signInfo.Hash)),
		C.CK_BYTE_PTR(unsafe.Pointer(&sig[0])), C.CK_ULONG_PTR(unsafe.Pointer(&siglen)))

	if rv != C.CKR_OK {
		logger.Errorf("m_SignSingle returned 0x%x\n", rv)
		rc.Error = fmt.Sprintf("m_SignSingle returned 0x%x\n", rv)
		return rc, fmt.Errorf("m_SignSingle returned 0x%x\n", rv)
	}

	rc.Sig = sig[:siglen]
	rc.Error = ""
	return rc, nil
}

func (s *grep11Server) VerifyP11ECDSA(c context.Context, verifyInfo *pb.VerifyInfo) (*pb.VerifyStatus, error) {
	rc := &pb.VerifyStatus{}

	rv := C.verifySingle((*C.uchar)(unsafe.Pointer(&verifyInfo.PubKey[0])), C.size_t(len(verifyInfo.PubKey)),
		C.CK_BYTE_PTR(unsafe.Pointer(&verifyInfo.Hash[0])), C.CK_ULONG(len(verifyInfo.Hash)),
		C.CK_BYTE_PTR(unsafe.Pointer(&verifyInfo.Sig[0])), C.CK_ULONG(len(verifyInfo.Sig)))

	if rv == C.CKR_SIGNATURE_INVALID {
		rc.Valid = false
	} else if rv != C.CKR_OK {
		logger.Errorf("m_VerifySingle returned 0x%x\n", rv)
		rc.Error = fmt.Sprintf("m_VerifySingle returned 0x%x\n", rv)
		return rc, fmt.Errorf("m_VerifySingle returned 0x%x\n", rv)
	} else {
		rc.Valid = true
	}

	rc.Error = ""
	return rc, nil
}

func (s *grep11Server) ImportECKey(c context.Context, verifyInfo *pb.ImportInfo) (*pb.ImportStatus, error) {
	rc := &pb.ImportStatus{}
	return rc, nil
}

func CreateTestServer(address, port, store string) {
	cleanKnownSessions(store)
	m := &grep11Manager{address, port, store}
	lis, err := net.Listen("tcp", m.address+":"+m.port)
	if err != nil {
		logger.Warningf("Failed to listen, continuing in hope that server is already running: %v", err)
		return
	}
	logger.Infof("Manager listening on %s", lis.Addr().String())
	grepManager := grpc.NewServer()
	pb.RegisterGrep11ManagerServer(grepManager, m)
	go grepManager.Serve(lis)

	time.Sleep(1000 * time.Microsecond)
}
