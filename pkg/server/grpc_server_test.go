package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseHost(t *testing.T) {
	tsts := []struct {
		name          string
		host          string
		expectNetwork string
		expectAddr    string
	}{
		{
			name:          "schemeless tcp host defaults to tcp",
			host:          "127.0.0.1:50051",
			expectNetwork: "tcp",
			expectAddr:    "127.0.0.1:50051",
		},
		{
			name:          "schemeless with only port defaults to tcp",
			host:          ":50051",
			expectNetwork: "tcp",
			expectAddr:    ":50051",
		},
		{
			name:          "unix socket",
			host:          "unix:///var/run/gobgp.socket",
			expectNetwork: "unix",
			expectAddr:    "/var/run/gobgp.socket",
		},
	}

	for _, tst := range tsts {
		t.Run(tst.name, func(t *testing.T) {
			gotNetwork, gotAddr := parseHost(tst.host)
			assert.Equal(t, tst.expectNetwork, gotNetwork)
			assert.Equal(t, tst.expectAddr, gotAddr)
		})
	}
}
