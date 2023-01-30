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
//go:build !windows
// +build !windows

// bits of modify-host-fib functionality that should be included in a non-supported
// platform. Any function that is called by code in the server package but not in the
// modify_host_fib files should have a stub version here, so it compiles on all platforms.

package server

import "fmt"

func newModifyHostFIBClient(s *BgpServer) (*modifyHostFIBClient, error) {
	return nil, fmt.Errorf("natively modifying the host FIB isn't supported on your platform.")
}

func (client *modifyHostFIBClient) stop() error {
	return fmt.Errorf("natively modifying the host FIB isn't supported on your platform.")
}
