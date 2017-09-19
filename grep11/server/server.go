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

CK_RV generateKeyPair (     unsigned char *oid,       size_t olen,
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

	"sync"

	"github.com/hyperledger/fabric/common/flogging"
	"github.com/spf13/viper"
	pb "github.com/vpaprots/bccsp/grep11/protos"
	"google.golang.org/grpc/keepalive"
)

var (
	logger           = flogging.MustGetLogger("grep11server")
	keepaliveOptions = KeepaliveOptions{
		ServerKeepaliveTime:    30,
		ServerKeepaliveTimeout: 5,
	}
	// This value is added to the current time to derive the next wakeup time for the activity watchdogs
	// One activity watchdog per server
	timeAdd time.Duration
)

// KeepAliveOptions is used to set the gRPC keepalive
// settings for grep11 servers
type KeepaliveOptions struct {
	// ServerKeepaliveTime is the duration in seconds after which if the server
	// does not see any activity from the client it pings the client to see
	// if it is alive
	ServerKeepaliveTime int
	// ServerKeepaliveTimeout is the duration the server waits for a response
	// from the client after sending a ping before closing the connection
	ServerKeepaliveTimeout int
}

func init() {
	C.m_init()
}

func Start(address, port, store string, sessionLimit int) error {
	cleanKnownSessions(store)

	m := &grep11Manager{address, port, store, sessionLimit}

	lis, err := net.Listen("tcp", m.address+":"+m.port)
	if err != nil {
		logger.Fatalf("failed to listen: %v", err)
	}
	logger.Infof("Manager listening on %s", lis.Addr().String())

	// Setup Keepalive options for grep11 manager server
	managerServerOpts := setupServerOptions()

	grpcManager := grpc.NewServer(managerServerOpts...)
	pb.RegisterGrep11ManagerServer(grpcManager, m)
	return grpcManager.Serve(lis)
}

type grep11Manager struct {
	address      string
	port         string
	store        string
	sessionLimit int
}

func (m *grep11Manager) Load(c context.Context, loadInfo *pb.LoadInfo) (*pb.LoadStatus, error) {
	rc := &pb.LoadStatus{}
	srvr := &grep11Server{}
	sessionCount := currentSessions()

	logger.Debugf("We already have %d sessions and session limit is set to %d", sessionCount, m.sessionLimit)

	if sessionCount < m.sessionLimit {
		pin := (*C.CK_UTF8CHAR)(unsafe.Pointer(&loadInfo.Pin[0]))
		pinLen := C.CK_ULONG(len(loadInfo.Pin))
		nonce := (*C.uchar)(unsafe.Pointer(&loadInfo.Nonce[0]))
		nonceLen := C.size_t(len(loadInfo.Nonce))
		pinBlob := (*C.uchar)(unsafe.Pointer(&srvr.pinblob[0]))
		pinBlobLen := (*C.size_t)(unsafe.Pointer(&srvr.pinbloblen))

		rv := C.login(pin, pinLen, nonce, nonceLen, pinBlob, pinBlobLen)

		if rv != C.CKR_OK {
			rc.Error = fmt.Sprintf("m_Login returned 0x%x\n", rv)
			logger.Errorf(rc.Error)
			return rc, fmt.Errorf(rc.Error)
		} else {
			rc.Session = true
			err := logSession(m.store, srvr.pinblob[:srvr.pinbloblen])
			if err != nil {
				logger.Warningf("Error recording pin %s [%s]", loadInfo.Pin, err)
			}
		}
	} else {
		logger.Warningf("Not using EP11 sessions, falling back to Domain Key encryption\n")
		rc.Session = false
		srvr.pinbloblen = 0
	}

	lis, err := net.Listen("tcp", m.address+":0")
	if err != nil {
		rc.Error = fmt.Sprintf("Failed to Listen: %v", err)
		rc.Address = ""
		return rc, fmt.Errorf(rc.Error)
	}

	// Setup Keepalive options for grep11 server
	grep11ServerOptions := setupServerOptions()
	srvr.grpcServer = grpc.NewServer(grep11ServerOptions...)

	rc.Error = ""
	rc.Address = lis.Addr().String()
	srvr.address = rc.Address

	// Setup logging, register and start new grep11 server
	if viper.GetBool("grep11.debugEnabled") {
		logging.SetLevel(logging.DEBUG, "grep11server_"+rc.Address)
	}

	srvr.logger = flogging.MustGetLogger("grep11server_" + rc.Address)

	pb.RegisterGrep11Server(srvr.grpcServer, srvr)
	go srvr.grpcServer.Serve(lis)

	// Initialize activity watchdog wakeup time
	timeAdd = time.Second * viper.GetDuration("grep11.serverTimeoutSecs")
	logger.Debugf("Value of timeAdd for server: %v", timeAdd)
	srvr.updateInactiveTimeout(newTime(timeAdd))

	// Activate watchdog for client activity to the grep11 server
	// One watchdog per grep11 server
	go srvr.activityWatchdog()

	// Inform as to whether the session or master key is being used
	if rc.Session {
		logger.Infof("Listening on %s for pin %s", rc.Address, loadInfo.Pin)
	} else {
		logger.Infof("Listening on %s with Master Key", rc.Address)
	}

	return rc, err
}

type grep11Server struct {
	pinblob           [1024]byte
	pinbloblen        int
	logger            *logging.Logger
	timeOutOnInactive time.Time
	timeMutex         sync.Mutex
	grpcServer        *grpc.Server
	address           string
}

func (s *grep11Server) GenerateECKey(c context.Context, generateInfo *pb.GenerateInfo) (*pb.GenerateStatus, error) {

	// Update inactive timeout value
	s.updateInactiveTimeout(newTime(timeAdd))

	rc := &pb.GenerateStatus{}
	var keyLen int = 1024
	var pubKeyLen int = 1024
	keyBlob := make([]byte, keyLen)
	pubKeyBlob := make([]byte, pubKeyLen)

	if generateInfo.Oid == nil {
		rc.Error = fmt.Sprintf("Encountered an invalid OID parameter [%v]\n", generateInfo.Oid)
		logger.Errorf(rc.Error)
		return rc, fmt.Errorf(rc.Error)
	}

	oid := (*C.uchar)(unsafe.Pointer(&generateInfo.Oid[0]))
	oidLen := C.size_t(len(generateInfo.Oid))
	keyBlobC := (*C.uchar)(unsafe.Pointer(&keyBlob[0]))
	keyBlobCLen := (*C.size_t)(unsafe.Pointer(&keyLen))
	pubKeyBlobC := (*C.uchar)(unsafe.Pointer(&pubKeyBlob[0]))
	pubKeyBlobCLen := (*C.size_t)(unsafe.Pointer(&pubKeyLen))
	pinBlobLen := C.size_t(s.pinbloblen)
	pinBlob := (*C.uchar)(unsafe.Pointer(&s.pinblob[0]))

	rv := C.generateKeyPair(oid, oidLen, pinBlob, pinBlobLen, keyBlobC, keyBlobCLen, pubKeyBlobC, pubKeyBlobCLen)

	if rv != C.CKR_OK {
		rc.Error = fmt.Sprintf("m_GenerateKeyPair returned 0x%x\n", rv)
		logger.Errorf(rc.Error)
		return rc, fmt.Errorf(rc.Error)
	}

	// Populate returning protobuf
	rc.PrivKey = keyBlob[:keyLen]
	rc.PubKey = pubKeyBlob[:pubKeyLen]
	rc.Error = ""
	return rc, nil
}

func (s *grep11Server) SignP11ECDSA(c context.Context, signInfo *pb.SignInfo) (*pb.SignStatus, error) {

	// Update inactive timeout value
	s.updateInactiveTimeout(newTime(timeAdd))

	rc := &pb.SignStatus{}

	var siglen int = 1024
	sig := make([]byte, siglen)

	if signInfo.PrivKey == nil {
		rc.Error = fmt.Sprintf("Encountered an invalid private key [%v]\n", signInfo.PrivKey)
		logger.Errorf(rc.Error)
		return rc, fmt.Errorf(rc.Error)
	}

	if signInfo.Hash == nil {
		rc.Error = fmt.Sprintf("Encountered an invalid hash value [%v]\n", signInfo.Hash)
		logger.Errorf(rc.Error)
		return rc, fmt.Errorf(rc.Error)
	}

	privKey := (*C.uchar)(unsafe.Pointer(&signInfo.PrivKey[0]))
	privKeyLen := C.size_t(len(signInfo.PrivKey))
	msgHash := C.CK_BYTE_PTR(unsafe.Pointer(&signInfo.Hash[0]))
	msgHashLen := C.CK_ULONG(len(signInfo.Hash))
	signature := C.CK_BYTE_PTR(unsafe.Pointer(&sig[0]))
	signatureLen := C.CK_ULONG_PTR(unsafe.Pointer(&siglen))

	rv := C.signSingle(privKey, privKeyLen, msgHash, msgHashLen, signature, signatureLen)

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

	// Update inactive timeout value
	s.updateInactiveTimeout(newTime(timeAdd))

	rc := &pb.VerifyStatus{}

	if verifyInfo.PubKey == nil {
		rc.Error = fmt.Sprintf("Encountered an invalid public key [%v]\n", verifyInfo.PubKey)
		logger.Errorf(rc.Error)
		return rc, fmt.Errorf(rc.Error)
	}

	if verifyInfo.Hash == nil {
		rc.Error = fmt.Sprintf("Encountered an invalid hash value [%v]\n", verifyInfo.Hash)
		logger.Errorf(rc.Error)
		return rc, fmt.Errorf(rc.Error)
	}

	if verifyInfo.Sig == nil {
		rc.Error = fmt.Sprintf("Encountered an invalid signature [%v]\n", verifyInfo.Sig)
		logger.Errorf(rc.Error)
		return rc, fmt.Errorf(rc.Error)
	}

	pubKey := (*C.uchar)(unsafe.Pointer(&verifyInfo.PubKey[0]))
	pubKeyLen := C.size_t(len(verifyInfo.PubKey))
	msgHash := C.CK_BYTE_PTR(unsafe.Pointer(&verifyInfo.Hash[0]))
	msgHashLen := C.CK_ULONG(len(verifyInfo.Hash))
	signature := C.CK_BYTE_PTR(unsafe.Pointer(&verifyInfo.Sig[0]))
	signatureLen := C.CK_ULONG(len(verifyInfo.Sig))

	rv := C.verifySingle(pubKey, pubKeyLen, msgHash, msgHashLen, signature, signatureLen)

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

// Activity watchdog for client activity with its associated grep11 server
// There is one watchdog service for every grep11 server started
func (s *grep11Server) activityWatchdog() {
	for {
		s.logger.Debugf("Sleeping until %v\n", s.timeOutOnInactive)
		sleepTime := -time.Now().Sub(s.timeOutOnInactive)
		time.Sleep(sleepTime)
		s.logger.Debug("Awake and checking time")
		if time.Now().After(s.timeOutOnInactive) {
			s.logger.Debugf("No activity has occurred with the client.  Shutting down GREP11 Server listening on: %s\n", s.address)
			s.grpcServer.Stop()
			return
		} else {
			s.updateInactiveTimeout(newTime(timeAdd))
			s.logger.Debug("Activity has occurred while sleeping. Updating new wakeup time.")
		}
	}
}

// Set the next time to wakeup and check for client activity for the associated grep11 server
func (s *grep11Server) updateInactiveTimeout(time time.Time) {
	s.timeMutex.Lock()
	defer s.timeMutex.Unlock()
	s.logger.Debugf("Updating next wake up time to: %v\n", time)
	s.timeOutOnInactive = time
}

// For testing only
func CreateTestServer(address, port, store string, sessionLimit int) {
	go Start(address, port, store, sessionLimit)
	time.Sleep(1000 * time.Microsecond)
}

func Cleanup(store string) {
	cleanKnownSessions(store)
}

// Setup up the GRPC server options
// Keepalive values are set as global variables located at the top of this file
func setupServerOptions() []grpc.ServerOption {
	var serverOpts []grpc.ServerOption
	kap := keepalive.ServerParameters{
		Time:    time.Duration(keepaliveOptions.ServerKeepaliveTime) * time.Second,
		Timeout: time.Duration(keepaliveOptions.ServerKeepaliveTimeout) * time.Second,
	}
	serverOpts = append(serverOpts, grpc.KeepaliveParams(kap))
	kep := keepalive.EnforcementPolicy{
		// needs to match clientKeepalive
		MinTime: time.Duration(keepaliveOptions.ServerKeepaliveTime) * time.Second,
		// allow keepalive w/o rpc
		PermitWithoutStream: true,
	}
	serverOpts = append(serverOpts, grpc.KeepaliveEnforcementPolicy(kep))
	return serverOpts
}

func newTime(timeDelta time.Duration) time.Time {
	return time.Now().Add(timeDelta)
}
