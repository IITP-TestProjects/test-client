package main

import (
	"context"
	"io"
	"log"
	cpb "test-client/proto_client"
	pb "test-client/proto_interface"
	"time"

	"test-client/golang-x-crypto/ed25519"
	"test-client/golang-x-crypto/ed25519/cosi"
)

var (
	round         uint64 = 0
	publicKey     ed25519.PublicKey
	secretKey     ed25519.PrivateKey
	secretR       *cosi.Secret
	committeeSize int
	testMsg       []byte = []byte("test message")
)

type cosignContext struct {
	publicKeys []ed25519.PublicKey
	aggCommit  []byte
	aggPubKey  []byte // 커밋값이 정해진 상태에서 사용됨
}

type legacySignState struct {
	message   string
	signature []byte
	publicKey []byte
}

func aggregateSignature(roundContext *roundState, cosignContext *cosignContext) []byte {
	log.Printf("Size of sigParts: %d Bytes\n",
		len(roundContext.sigParts)*len(roundContext.sigParts[0]))
	//log.Println("part Sign length: ", len(roundContext.sigParts))
	cosigners := cosi.NewCosigners(cosignContext.publicKeys, nil)

	if len(roundContext.sigParts) != len(cosignContext.publicKeys) {
		log.Printf("mismatch: sig=%d pubKeys=%d wait",
			len(roundContext.sigParts), len(cosignContext.publicKeys))
		return nil
	}

	aggregatedSign := cosigners.AggregateSignature(
		cosignContext.aggCommit, roundContext.sigParts)

	return aggregatedSign
}

func verifySignature(cosignContext *cosignContext, aggregatedSign []byte) bool {
	//log.Println("Aggregated Signature: ", aggregatedSign)
	log.Printf("aggSign: %x\n", aggregatedSign)
	log.Printf("Size of aggSign: %d Bytes\n", len(aggregatedSign))
	log.Println("--------------Start Verify--------------")
	start := time.Now()
	ok := cosi.Verify(cosignContext.publicKeys, nil, testMsg, aggregatedSign)
	duration := time.Since(start)
	log.Printf("Verify Result: %t, Duration: %s\n", ok, duration)
	log.Println("--------------End Verify--------------")
	return ok
}

func (t *transferServer) setCosignContext(msg *pb.FinalizedCommittee) {
	t.mu.Lock()
	defer t.mu.Unlock()
	var pubKeys []ed25519.PublicKey
	for _, pk := range msg.PublicKeys {
		pubKeys = append(pubKeys, ed25519.PublicKey(pk))
	}

	// 커밋값이 정해진 상태에서 커밋값을 사용
	t.cosignContext = &cosignContext{
		publicKeys: pubKeys,
		aggPubKey:  msg.AggregatedPubKey,
	}
}

func (ts *transferServer) initRoundContext() {
	// roundContext 초기화
	if ts.roundContext == nil {
		ts.roundContext = make(map[uint64]*roundState)
	}
	// roundState 초기화
	if _, ok := ts.roundContext[round]; !ok {
		ts.roundContext[round] = &roundState{}
	}
}

// [NonRPC] 내부에서 사용하는 함수
func (ts *transferServer) subscribe(c pb.MeshClient, priCli cpb.TransferSignClient, nodeId string) error {
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

			// 커미티가 정해진 상태에서 커밋값만 받아왔다면 저장된 aggPubKey를 사용
			ts.initRoundContext()

			// 커미티가 이미 정해져 aggCommit만 받는경우 aggPubKey는 넘어오지 않음
			if msg.AggregatedPubKey != nil {
				ts.setCosignContext(msg)
				committeeSize = len(msg.NodeId)
			}
			ts.cosignContext.aggCommit = msg.AggregatedCommit

			sigPart := cosi.Cosign(secretKey, secretR, testMsg,
				ts.cosignContext.aggPubKey, msg.AggregatedCommit)

			log.Printf("generate sigPart: %x\n", sigPart)

			if nodeId != "node1" {
				time.Sleep(5 * time.Second) //임시코드(node1 우선실행 최대한 보장) 다른방법을 찾아봐.
				sendPrimaryNodeForAggregateSignature(priCli, nodeId, sigPart, msg.Round)
			} else {
				if msg.NodeId != nil {
					log.Println("Committee:", msg.NodeId)
				}
				ts.mu.Lock()
				ts.roundContext[msg.Round].sigParts =
					append(ts.roundContext[msg.Round].sigParts, sigPart)
				log.Printf("\nNode1 append partsign\n")
				ts.mu.Unlock()
			}
		}
	}()
	return nil
}
