// Copyright (C) 2015 Nippon Telegraph and Telephone Corporation.
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
//go:build windows
// +build windows

package server

import (
	"github.com/osrg/gobgp/v3/pkg/log"
)

func newModifyHostFIBClient(s *BgpServer) (*modifyHostFIBClient, error) {
	client := &modifyHostFIBClient{
		server: s,
	}
	go client.loop()
	return client, nil
}

func (client *modifyHostFIBClient) loop() {
	w := client.server.watch([]watchOption{
		watchBestPath(true),
		watchPostUpdate(true, ""),
	}...)
	defer w.Stop()

	for {
		select {
		case ev := <-w.Event():
			switch msg := ev.(type) {
			case *watchEventBestPath:
				client.server.logger.Info("watchEventBestPath",
					log.Fields{
						"Topic": "ModifyHostFIB",
						"Msg":   msg,
					},
				)
			case *watchEventUpdate:
				client.server.logger.Info("watchEventUpdate",
					log.Fields{
						"Topic": "ModifyHostFIB",
						"Msg":   msg,
					},
				)
			}
		}
	}
}
