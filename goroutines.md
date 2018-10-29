cmd/gobgpd/main.go:main
    -> go bgpServer.Serve()
        pkg/server/peer.go:startFSMHandler (dynamic neighbor)
        pkg/server/server.go:handleFSMMessage
            -> go peer.stopFSM()
            -> go func(... // For each llgr family
            pkg/server/peer.go:startFSMHandler (FSM_MSG_STATE_CHANGE
    pkg/server/peer.go:newDynamicPeer
        pkg/server/peer.go:NewPeer


pkg/server/peer.go:startFSMHandler
    pkg/server/fsm.go:NewFSMHandler
        -> fsm.t.Go(h.loop) pkg/server/fsm.go:loop
           -> h.t.Go(f) <- This is a thing just to start the h.t.Go stuff
               pkg/server/fsm.go:opensent
                   -> h.t.Go(h.recvMessage) pkg/server/fsm.go:recvMessage Uses this h.msgCh thing
               pkg/server/fsm.go:openconfirm
                   -> h.t.Go(h.recvMessage)
               pkg/server/fsm.go:established
                   -> h.t.Go(h.sendMessageloop)
               pkg/server/fsm.go:established
                   -> h.t.Go(h.recvMessageloop) pkg/server/fsm.go:recvMessageloop Uses h.msgCh

pkg/server/server.go:UpdateNeighbor
    pkg/server/server.go:updateNeighbor
        pkg/server/server.go: addNeighbor

pkg/server/server.go:UpdatePeerGroup
    pkg/server/server.go:updatePeerGroup

pkg/server/server.go:AddPeer
    pkg/server/server.go: addNeighbor

pkg/server/peer.go:NewPeer
   pkg/server/fsm.go:NewFSM fsm.t.Go(fsm.connectLoop)
       -> fsm.t.Go(fsm.connectLoop) pkg/server/fsm.go:connectLoop
           -> go connect() // closure defined here

pkg/server/server.go:DeletePeer
    pkg/server/server.go:deleteNeighbor

// This is an entry point
pkg/server/server.go StartBGP:
    pkg/server/server.go:NewTCPListener: go func()
        -> go func()

pkg/server/server.go:StopBGP
    pkg/server/server.go:deleteNeighbor

pkg/server/server.go:addNeighbor
    pkg/server/peer.go:NewPeer
    pkg/server/peer.go:startFSMHandler

pkg/server/server.go:deleteNeighbor
    -> go n.stopFSM()

pkg/server/server.go:Watch
    -> go w.loop()
