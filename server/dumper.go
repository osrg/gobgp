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

package server

import (
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/osrg/gobgp/packet"
	"gopkg.in/tomb.v2"
	"os"
	"time"
)

type dumper struct {
	t  tomb.Tomb
	ch chan *broadcastBGPMsg
}

func (d *dumper) sendCh() chan *broadcastBGPMsg {
	return d.ch
}

func (d *dumper) shutdown() error {
	d.t.Kill(nil)
	var timeoutCh chan struct{}
	e := time.AfterFunc(time.Second*10, func() {
		timeoutCh <- struct{}{}
	})
	select {
	case <-d.t.Dead():
		log.Info("shut down bmp client")
		e.Stop()
	case <-timeoutCh:
		return fmt.Errorf("failed to shutdown mrt dumper")
	}
	return nil
}

func newDumper(filename string) (*dumper, error) {
	f, err := os.Create(filename)
	if err != nil {
		return nil, err
	}

	ch := make(chan *broadcastBGPMsg, 16)

	d := &dumper{
		ch: ch,
	}

	d.t.Go(func() error {
		for {
			select {
			case <-d.t.Dying():
				return nil
			case m := <-ch:
				subtype := bgp.MESSAGE_AS4
				mp := bgp.NewBGP4MPMessage(m.peerAS, m.localAS, 0, m.peerAddress.String(), m.localAddress.String(), m.fourBytesAs, m.message)
				if m.fourBytesAs == false {
					subtype = bgp.MESSAGE
				}
				bm, err := bgp.NewMRTMessage(uint32(time.Now().Unix()), bgp.BGP4MP, subtype, mp)
				if err != nil {
					log.WithFields(log.Fields{
						"Topic": "mrt",
						"Data":  m,
					}).Warn(err)
					continue
				}
				buf, err := bm.Serialize()
				if err != nil {
					log.WithFields(log.Fields{
						"Topic": "mrt",
						"Data":  m,
					}).Warn(err)
				} else {
					f.Write(buf)
				}
			}
		}
	})

	return d, nil
}
