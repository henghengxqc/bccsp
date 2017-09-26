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
package main

import (
	"strings"

	"os"
	"os/signal"
	"syscall"

	"fmt"

	"github.com/hyperledger/fabric/common/flogging"
	logging "github.com/op/go-logging"
	"github.com/spf13/viper"
	"github.com/vpaprots/bccsp/grep11/server"
)

var (
	logger = flogging.MustGetLogger("grep11server")
)

func main() {

	// For environment variables.
	viper.SetEnvPrefix("GREP11")
	viper.SetConfigType("yaml")
	viper.AutomaticEnv()
	viper.AddConfigPath(".")
	viper.AddConfigPath("/etc/ep11server")
	replacer := strings.NewReplacer(".", "_")
	viper.SetEnvKeyReplacer(replacer)

	viper.SetDefault("grep11.address", "localhost")
	viper.SetDefault("grep11.port", "9876")
	viper.SetDefault("grep11.store", "/tmp/sessionStore.db")
	viper.SetDefault("grep11.sessionLimit", 0)
	viper.SetDefault("grep11.serverTimeoutSecs", 60*60*2) // 2 hour timeout
	viper.SetDefault("grep11.debugEnabled", false)

	viper.SetConfigName("grep11server")

	err := viper.ReadInConfig() // Find and read the config file
	if err != nil {             // Handle errors reading the config file
		logger.Fatalf("Error when reading %s config file: %s", "grep11server", err)
	}

	address := viper.GetString("grep11.address")
	port := viper.GetString("grep11.port")
	store := viper.GetString("grep11.store")
	sessionLimit := viper.GetInt("grep11.sessionLimit")

	if viper.GetBool("grep11.debugEnabled") {
		logging.SetLevel(logging.DEBUG, "grep11server")
	}

	serve := make(chan error)

	// Allow the ep11server to receive system signals
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigs
		logger.Debugf("signal received: %s", sig)

		// Cleanup sessions
		server.Cleanup(store)
		serve <- nil
	}()

	// Start the GRPC server
	go func() {
		var grpcErr error
		logger.Info("Starting EP11 server")
		if grpcErr = server.Start(address, port, store, sessionLimit); grpcErr != nil {
			grpcErr = fmt.Errorf("GRPC server exited with error: %s", grpcErr)
		}
		serve <- grpcErr
	}()

	// Terminate EP11 server if system signal or GRPC error occurs
	<-serve
	logger.Info("EP11 Server has been shutdown")
}
