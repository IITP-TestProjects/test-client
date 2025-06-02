package main

import (
	"context"
	"io"
	"log"
	"net"
	"sync"
	cpb "test-client/proto_client"
	pb "test-client/proto_interface"
	"time"

	"github.com/bford/golang-x-crypto/ed25519"
	"github.com/bford/golang-x-crypto/ed25519/cosi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	round     uint64 = 0
	publicKey ed25519.PublicKey
	secretKey ed25519.PrivateKey
	secretR   *cosi.Secret
	testMsg   []byte = []byte("test message")
)

type roundState struct {
	nodeId        string
	committeeSize int
	publicKeys    []ed25519.PublicKey
	aggCommit     []byte
	sigParts      []cosi.SignaturePart
	count         int
}

type legacySignState struct {
	message   string
	signature []byte
	publicKey []byte
}

type transferServer struct {
	cpb.UnimplementedTransferSignServer

	mu            sync.Mutex
	roundContext  map[uint64]*roundState
	legacyContext []legacySignState
}

func aggregateSignature(roundContext *roundState) []byte {
	log.Printf("Size of sigParts: %d Bytes\n",
		len(roundContext.sigParts)*len(roundContext.sigParts[0]))
	//log.Println("--------------Start Aggregate Signature---------------")
	//log.Println("part Sign length: ", len(roundContext.sigParts))
	cosigners := cosi.NewCosigners(roundContext.publicKeys, nil)

	if len(roundContext.sigParts) != len(roundContext.publicKeys) {
		log.Printf("mismatch: sig=%d pubKeys=%d wait",
			len(roundContext.sigParts), len(roundContext.publicKeys))
		return nil
	}

	aggregatedSign := cosigners.AggregateSignature(
		roundContext.aggCommit, roundContext.sigParts)

	//log.Println("------------------Aggregation Done-------------------")

	return aggregatedSign
}

func verifySignature(roundContext *roundState, aggregatedSign []byte) bool {
	//log.Println("Aggregated Signature: ", aggregatedSign)
	log.Printf("Size of aggSign: %d Bytes", len(aggregatedSign))
	log.Println("--------------Start Verify--------------")
	start := time.Now()
	ok := cosi.Verify(roundContext.publicKeys, nil, testMsg, aggregatedSign)
	duration := time.Since(start)
	log.Printf("Verify Result: %t, Duration: %s\n", ok, duration)
	log.Println("--------------End Verify--------------")
	return ok
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
	roundContext.count++

	// 해당 라운드에서 정해진 모든 커미티로부터 서명을 집계한 경우
	ready := roundContext.count == roundContext.committeeSize

	if !ready {
		return &cpb.Ack{Ok: true}, nil
	}
	if len(roundContext.sigParts) != len(roundContext.publicKeys) {
		log.Printf("mismatch: sig=%d pubKeys=%d wait",
			len(roundContext.sigParts), len(roundContext.publicKeys))
		return &cpb.Ack{Ok: true}, nil
	}
	log.Println("All parts received, round:", sigRound)

	//집계한 서명을 압축.
	aggregatedSign := aggregateSignature(roundContext)
	if aggregatedSign == nil {
		return &cpb.Ack{Ok: false}, nil
	}

	//압축한 서명이 올바른지 검증
	ok := verifySignature(roundContext, aggregatedSign)
	if !ok {
		return &cpb.Ack{Ok: false}, nil
	}

	//roundContext.count = 0
	//roundContext.sigParts = nil
	roundContext = nil

	return &cpb.Ack{Ok: true}, nil
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

func (t *transferServer) setCommitteeInfo(msg *pb.FinalizedCommittee) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.roundContext == nil {
		t.roundContext = make(map[uint64]*roundState)
	}

	pubKeys := make([]ed25519.PublicKey, 0, len(msg.PublicKeys))
	for _, pk := range msg.PublicKeys {
		if len(pk) != ed25519.PublicKeySize {
			log.Printf("[%s]Invalid public key size detected\n", msg.NodeId)
			continue
		}
		pubKeys = append(pubKeys, ed25519.PublicKey(pk))
	}
	st := &roundState{
		committeeSize: len(msg.NodeId),
		publicKeys:    pubKeys,
		aggCommit:     msg.AggregatedCommit,
	}
	t.roundContext[msg.Round] = st
}

// [NonRPC] 내부에서 사용하는 함수
func subscribe(c pb.MeshClient, nodeId string, ts *transferServer) error {
	stream, err := c.JoinNetwork(context.Background(),
		&pb.NodeAccount{NodeId: nodeId})
	if err != nil {
		return err
	}

	// receive loop(FinalizedCommittee를 수신)
	go func() {
		for {
			msg, err := stream.Recv()
			if err == io.EOF {
				log.Println("stream closed")
				return
			}
			if err != nil {
				log.Printf("recv error: %v", err)
				return
			}
			//log.Printf("[Receive!], [AggregatedPublicKey: %x]", msg.AggregatedPubKey)

			//특정 라운드에 따른 committee 개수를 저장, publickeys를 저장
			ts.setCommitteeInfo(msg)

			//committee 정보를 수신 받은 후, 서명을 진행하고 이것을 primary node에 전송
			sigPart := cosi.Cosign(secretKey, secretR, testMsg,
				msg.AggregatedPubKey, msg.AggregatedCommit)

			if nodeId != "node1" {
				time.Sleep(5 * time.Second) //임시코드(node1 우선실행 최대한 보장) 다른방법을 찾아봐.
				sendPrimaryNodeForAggregateSignature(nodeId, sigPart, msg.Round)
			} else {
				ts.mu.Lock()
				ts.roundContext[msg.Round].sigParts =
					append(ts.roundContext[msg.Round].sigParts, sigPart)
				ts.roundContext[msg.Round].count++
				log.Printf("\nNode1 append partsign\n")
				ts.mu.Unlock()
			}
		}
	}()
	return nil
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

// commit 생성하는 코드 및 커밋 압축하는 코드 필요:
//
