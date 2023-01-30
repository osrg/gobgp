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

// bits of modify-host-fib functionality that should be included for all platforms.

package server

import (
	"context"
	"sync"
)

type modifyHostFIBClient struct {
	// global parent struct
	server *BgpServer
	// called to stop the loop() goroutine when we shut down
	stopLoop context.CancelFunc
	// blocks until loop() is fully shut down after calling stopLoop
	loopFinished *sync.WaitGroup
}
