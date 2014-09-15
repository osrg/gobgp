// Copyright (C) 2014 Nippon Telegraph and Telephone Corporation.
//
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

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"log/syslog"
	"net"
	"os"

	"github.com/osrg/gobgp/packet"
)

const (
	DEFAULT_BMPD_HOST = "0.0.0.0"
	DEFAULT_BMPD_PORT = "11019"
)

func processBMPClinet(conn net.Conn) {
	tcpConn := conn.(*net.TCPConn)
	defer tcpConn.Close()

	for {
		msg, err := bgp.ReadBMPMessage(tcpConn)
		if err != nil {
			fmt.Println(err)
			log.Println("BMP client disconnected", conn.RemoteAddr())
			break
		}
		j, _ := json.Marshal(msg)
		log.Println(string(j))
	}
}

func main() {
	logwriter, err := syslog.New(syslog.LOG_INFO, "bmpd")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	log.SetOutput(logwriter)

	serverHost := os.Getenv("BMPD_HOST")
	if serverHost == "" {
		serverHost = DEFAULT_BMPD_HOST
	}

	serverPort := os.Getenv("BMPD_PORT")
	if serverPort == "" {
		serverPort = DEFAULT_BMPD_PORT
	}

	listener, err := net.Listen("tcp", serverHost+":"+serverPort)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	log.Println("listening on", serverHost+":"+serverPort)

	for {
		conn, err := listener.Accept()
		log.Println("BMP client connected", conn.RemoteAddr())
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		go processBMPClinet(conn)
	}
}
