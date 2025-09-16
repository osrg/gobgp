// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package grpcutil

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

var logger = logrus.New()

type TLSReloader struct {
	interval     int
	certFilePath string
	keyFilePath  string
	caFilePath   string

	mu            sync.Mutex
	currentConfig *tls.Config
}

func NewTLSReloader(interval int, certFilePath, keyFilePath, caFilePath string) (*TLSReloader, error) {
	reloader := TLSReloader{
		interval:     interval,
		certFilePath: certFilePath,
		keyFilePath:  keyFilePath,
		caFilePath:   caFilePath,
	}

	err := reloader.Reload()
	if err != nil {
		return nil, err
	}

	if reloader.interval > 0 {
		go reloader.Watch()
	}

	return &reloader, nil
}

func (r *TLSReloader) Watch() {
	for {
		time.Sleep(time.Duration(r.interval))
		logger.Debug("Reloading certificates")
		err := r.Reload()
		if err != nil {
			logger.Warnf("Error reloading certificates. Keeping existing ones. %s", err)
		} else {
			logger.Debug("Finished reloading certificates")
		}
	}
}

func (r *TLSReloader) Reload() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	// server cert/key
	cert, err := tls.LoadX509KeyPair(r.certFilePath, r.keyFilePath)
	if err != nil {
		logger.Warnf("Failed to load server certificate/key pair: %v", err)
		return err
	}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2"}}

	// client CA
	if len(r.caFilePath) != 0 {
		tlsConfig.ClientCAs = x509.NewCertPool()
		pemCerts, err := os.ReadFile(r.caFilePath)
		if err != nil {
			logger.Warnf("Failed to load client CA certificates from %q: %v", r.caFilePath, err)
			return err
		}
		if ok := tlsConfig.ClientCAs.AppendCertsFromPEM(pemCerts); !ok {
			logger.Warnf("No valid client CA certificates in %q", r.caFilePath)
			return err
		}
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}
	r.currentConfig = tlsConfig
	return nil
}

func (r *TLSReloader) getConfigForClient(_ *tls.ClientHelloInfo) (*tls.Config, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.currentConfig, nil
}

func (r *TLSReloader) GetMainConfig() *tls.Config {
	return &tls.Config{
		GetConfigForClient: r.getConfigForClient,
	}
}
