// Copyright (C) 2026 The GoBGP Authors.
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

//go:build openbsd

package netutils

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSaAddRejectsNonIPv4Address(t *testing.T) {
	// An IPv6 neighbor and a dynamic neighbor prefix both reach saAdd
	// through SetTCPMD5SigSockopt. Neither fits in sockaddr_in, so saAdd
	// must return an error before it opens the PF_KEY socket.
	for _, addr := range []string{"2001:db8::1", "10.0.0.0/24"} {
		require.Error(t, saAdd(addr, "secret"), addr)
	}
	require.Zero(t, fd)
}
