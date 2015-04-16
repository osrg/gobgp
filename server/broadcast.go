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

package server

type broadcast struct {
	c chan broadcast
	v interface{}
}

type Broadcaster struct {
	Listenc chan chan (chan broadcast)
	Sendc   chan<- interface{}
}

type Receiver struct {
	C chan broadcast
}

func NewBroadcaster() Broadcaster {
	listenc := make(chan (chan (chan broadcast)))
	sendc := make(chan interface{})

	go func() {
		currc := make(chan broadcast, 1)
		for {
			select {
			case v := <-sendc:
				if v == nil {
					currc <- broadcast{}
					return
				}

				c := make(chan broadcast, 1)
				b := broadcast{c: c, v: v}
				currc <- b
				currc = c
			case r := <-listenc:
				r <- currc
			}
		}
	}()
	return Broadcaster{
		Listenc: listenc,
		Sendc:   sendc,
	}
}

func (b Broadcaster) Listen() Receiver {
	c := make(chan chan broadcast, 0)
	b.Listenc <- c
	return Receiver{<-c}
}

func (b Broadcaster) Write(v interface{}) { b.Sendc <- v }
