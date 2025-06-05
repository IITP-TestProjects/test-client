package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"log"
	"time"

	cpb "test-client/proto_client"
)

func legacySignScenario(nodeId string, t *transferServer, priCon cpb.TransferSignClient) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("Legacy GenerateKey failed: %v", err)
	}

	msg := []byte("legacy_test_message")
	signature := ed25519.Sign(priv, msg)
	if nodeId != "node1" {
		/* conn, err := grpc.NewClient("client1:50052",
			grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			log.Fatal(err)
		}
		defer conn.Close()
		client := cpb.NewTransferSignClient(conn) */

		time.Sleep(5 * time.Second) // 임시 코드(node1 우선실행 최대한 보장)
		// Legacy Sign 정보를 전송
		_, err = priCon.GetLegacySign(context.Background(),
			&cpb.GetLegacySignRequest{
				Message:   string(msg),
				Signature: signature,
				PublicKey: pub,
			})
		if err != nil {
			log.Fatalf("GetLegacySign failed: %v", err)
		}
	} else {
		// node1인 경우, 직접 legacyContext에 추가
		t.mu.Lock()
		t.legacyContext = append(t.legacyContext, legacySignState{
			message:   string(msg),
			signature: signature,
			publicKey: pub,
		})
		t.mu.Unlock()
	}

	//이후에는 GetLegacySign RPC에서 진행
}

func (t *transferServer) GetLegacySign(
	_ context.Context, req *cpb.GetLegacySignRequest) (*cpb.Ack, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.legacyContext = append(t.legacyContext, legacySignState{
		message:   req.Message,
		signature: req.Signature,
		publicKey: req.PublicKey,
	})

	if len(t.legacyContext) == node_num {
		log.Printf("Size of legacySigns: %d Bytes",
			len(t.legacyContext[0].signature)*len(t.legacyContext))
		log.Printf("-------------- Start Legacy Sign Verify--------------\n")
		start := time.Now()
		for _, legacySign := range t.legacyContext {
			publicKey := ed25519.PublicKey(legacySign.publicKey)
			message := []byte(legacySign.message)
			signature := legacySign.signature
			if !ed25519.Verify(publicKey, message, signature) {
				log.Printf("Legacy Sign verification failed for message: %s\n", legacySign.message)
				return &cpb.Ack{Ok: false}, nil
			}
		}
		duration := time.Since(start)
		log.Printf("Legacy verify PASS\n")
		log.Printf("Duration: %s\n", duration)
		log.Printf("-------------- Start Legacy Sign Verify--------------\n")

		return &cpb.Ack{Ok: true}, nil
	}
	return &cpb.Ack{Ok: true}, nil
}
