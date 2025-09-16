package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"net"
	"sort"
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
	rosterHash []byte // 정렬 기반 로스터 해시(SHA-256)
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

// 공개키 목록([][]byte)로 정렬 기반 로스터 해시 생성
func computeRosterHash(pubKeys [][]byte) []byte {
	if len(pubKeys) == 0 {
		return nil
	}
	arr := make([][]byte, 0, len(pubKeys))
	for _, pk := range pubKeys {
		b := make([]byte, len(pk))
		copy(b, pk)
		arr = append(arr, b)
	}
	sort.Slice(arr, func(i, j int) bool { return bytes.Compare(arr[i], arr[j]) < 0 })
	h := sha256.New()
	for _, b := range arr {
		h.Write(b)
	}
	return h.Sum(nil)
}

// 메시지 바인딩: m' = SHA-256(m || rosterHash)
func bindMessage(msg []byte, rosterHash []byte) []byte {
	if len(rosterHash) == 0 {
		return msg
	}
	h := sha256.New()
	h.Write(msg)
	h.Write(rosterHash)
	return h.Sum(nil)
}

// [NonRPC] 내부에서 사용하는 함수
func (ts *transferServer) subscribe(c pb.MeshClient, priCli cpb.TransferSignClient, nodeId string) error {
	stream, err := c.JoinNetwork(context.Background(),
		&pb.CommitteeCandidateInfo{NodeId: nodeId})
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

			boundMsg := bindMessage(testMsg, ts.cosignContext.rosterHash)
			sigPart := cosi.Cosign(secretKey, secretR, boundMsg,
				ts.cosignContext.aggPubKey, msg.AggregatedCommit)

			log.Printf("generate sigPart: %x\n", sigPart)

			//분기: 리더노드인 경우, sigPart를 브로드캐스트
			log.Println("Leader NodeId:", msg.LeaderNodeId)
			if nodeId != "node1" /* "node1" */ {
				time.Sleep(5 * time.Second) //임시코드(리더노드 우선실행 최대한 보장) 다른방법을 찾아봐.
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

func getLocalIP() (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String(), nil
			}
		}
	}
	return "", fmt.Errorf("외부 통신이 가능한 로컬 IP 주소를 찾을 수 없습니다")
}
