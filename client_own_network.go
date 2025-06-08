package main

import (
	"context"
	"log"
	"net"
	"sync"
	cpb "test-client/proto_client"

	"github.com/bford/golang-x-crypto/ed25519/cosi"
	"google.golang.org/grpc"
)

type roundState struct {
	nodeId   string
	sigParts []cosi.SignaturePart
}

type transferServer struct {
	cpb.UnimplementedTransferSignServer

	mu            sync.Mutex
	roundContext  map[uint64]*roundState
	cosignContext *cosignContext
	legacyContext []legacySignState
	subs          map[string]chan *cpb.InternalBroadcastData

	wait chan struct{}
}

func startClientGrpcServer(ts *transferServer) {
	s := grpc.NewServer()
	cpb.RegisterTransferSignServer(s, ts)

	lis, err := net.Listen("tcp", ":50052")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	log.Println("TransferSignServer is running on port 50052")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

// [RPC]part Signature를 받으면 이것들을 모아서 압축해서 response해야함.
func (t *transferServer) GetPartSign(
	_ context.Context, partSign *cpb.GetPartSignRequest) (*cpb.Ack, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	sigRound := partSign.Round
	roundContext := t.roundContext[sigRound]

	//client 노드로부터 서명을 집계함.
	roundContext.sigParts = append(roundContext.sigParts, partSign.PartSign)
	roundContext.nodeId = partSign.NodeId

	// 해당 라운드에서 정해진 모든 커미티로부터 서명을 집계한 경우
	ready := len(roundContext.sigParts) == committeeSize

	if !ready {
		return &cpb.Ack{Ok: true}, nil
	}
	if len(roundContext.sigParts) != len(t.cosignContext.publicKeys) {
		log.Printf("mismatch: sig=%d pubKeys=%d wait",
			len(roundContext.sigParts), len(t.cosignContext.publicKeys))
		return &cpb.Ack{Ok: true}, nil
	}
	log.Println("All parts received, round:", sigRound)

	//집계한 서명을 압축.
	aggregatedSign := aggregateSignature(roundContext, t.cosignContext)
	if aggregatedSign == nil {
		return &cpb.Ack{Ok: false}, nil
	}

	//압축한 서명이 올바른지 검증
	ok := verifySignature(t.cosignContext, aggregatedSign)
	if !ok {
		return &cpb.Ack{Ok: false}, nil
	}

	delete(t.roundContext, sigRound) //Garbage Collection

	close(t.wait)
	t.broadcast(&cpb.InternalBroadcastData{
		Round: sigRound,
	})
	return &cpb.Ack{Ok: true}, nil
}

func sendPrimaryNodeForAggregateSignature(
	priCli cpb.TransferSignClient, nodeId string, sigPart cosi.SignaturePart, aggRound uint64) {
	// 서명한 데이터를 primary node에 전송해서 sign을 압축
	if nodeId != "node1" {
		_, err := priCli.GetPartSign(context.Background(),
			&cpb.GetPartSignRequest{
				NodeId:   nodeId,
				Round:    aggRound,
				PartSign: sigPart,
			})
		if err != nil {
			log.Fatalf("GetPartSign failed: %v", err)
		}
	}
}

func (t *transferServer) InternalBroadcaster(
	ib *cpb.InternalSubscribe, stream cpb.TransferSign_InternalBroadcasterServer) error {
	nodeId := ib.NodeId
	ch := make(chan *cpb.InternalBroadcastData, 100)

	t.mu.Lock()
	if t.subs == nil {
		t.subs = make(map[string]chan *cpb.InternalBroadcastData)
	}
	t.subs[nodeId] = ch

	t.mu.Unlock()

	defer func() {
		t.mu.Lock()
		delete(t.subs, nodeId)
		t.mu.Unlock()
		close(ch)
		log.Printf("node %s left", nodeId)
	}()

	for {
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case msg := <-ch:
			if err := stream.Send(msg); err != nil {
				return err
			}
		}
	}
}

func (t *transferServer) broadcast(msg *cpb.InternalBroadcastData) {
	for _, ch := range t.subs {
		select {
		case ch <- msg:
		default:
		}
	}
}

func (t *transferServer) subscribeDoneSignal(c cpb.TransferSignClient, nodeId string) error {
	stream, err := c.InternalBroadcaster(context.Background(),
		&cpb.InternalSubscribe{NodeId: nodeId})
	if err != nil {
		return err
	}

	go func() {
		for {
			msg, err := stream.Recv()
			if err != nil {
				return
			}
			if msg.Round == round {
				close(t.wait)
			}
		}
	}()
	return nil
}
