package main

import (
	"context"
	"log"
	"net"
	"sync"
	cpb "test-client/proto_client"

	"github.com/bford/golang-x-crypto/ed25519/cosi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type transferServer struct {
	cpb.UnimplementedTransferSignServer

	mu            sync.Mutex
	roundContext  map[uint64]*roundState
	cosignContext *cosignContext
	legacyContext []legacySignState
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
	return &cpb.Ack{Ok: true}, nil
}

func sendPrimaryNodeForAggregateSignature(nodeId string, sigPart cosi.SignaturePart, aggRound uint64) {
	// 서명한 데이터를 primary node에 전송해서 sign을 압축
	if nodeId != "node1" {
		conn, err := grpc.NewClient("client1:50052",
			grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			log.Fatal(err)
		}
		defer conn.Close()

		client := cpb.NewTransferSignClient(conn)
		_, err = client.GetPartSign(context.Background(),
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
