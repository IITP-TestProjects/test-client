package main

import (
	"context"
	"flag"
	"io"
	"log"

	pb "test-client/proto_interface"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var round uint64 = 0

func main() {
	nodeId := flag.String("node", "node1", "node ID to subscribe. -node=<nodeId>")
	flag.Parse()

	if err := runClient(*nodeId); err != nil {
		log.Fatal(err)
	}
}

func runClient(nodeId string) error {
	//grpc.Dial하는 함수의 경우, docker기반 테스트 환경이므로 해당 container명 기입함.
	conn, err := grpc.NewClient("interface-server1:50051",
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	client := pb.NewMeshClient(conn)
	firstScenario(client, nodeId)

	//실제 구독 시작
	if err := subscribe(client, nodeId); err != nil {
		return err
	}

	select {}
}

func subscribe(c pb.MeshClient, nodeId string) error {
	stream, err := c.JoinNetwork(context.Background(),
		&pb.NodeAccount{NodeId: nodeId})
	if err != nil {
		return err
	}

	// receive loop
	go func() {
		messageCount := 0
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
			log.Printf("[Received] %s", string(msg.AggregatedPubKey))
			messageCount++

			//메시지를 10번초과로 수신한 경우, LeaveNetwork API를 호출해 graceful-shutdown
			if messageCount > 5 {
				c.LeaveNetwork(context.Background(),
					&pb.NodeAccount{NodeId: nodeId})
				return
			}
		}
	}()
	return nil
}

// o1만에 검증가능한 sign 시연
func firstScenario(c pb.MeshClient, nodeId string) {
	// 1. JoinNetwork API를 호출해 CEF를 subscribe
	subscribe(c, nodeId)
	seed := "hungry"

	pk, sk := generateKeys()

	// 2. vrf 실행
	vrfProof := generateVrfOutput(seed, pk, sk)

	// 2. Server로 Request를 보내 서명압축에 필요한 정보와 자신을 식별할 수 있는 ID를 전송
	// 이후 과정은 서버에서 진행 및 연결한 Subscribe channel로 정보가 내려옴.
	ack, err := c.RequestCommittee(context.Background(),
		&pb.CommitteeCandidateInfo{
			Round:  round,
			NodeId: nodeId,

			Seed:      seed,
			Proof:     vrfProof,
			PublicKey: pk,

			MetricData1: "test-metric1",
			MetricData2: "test-metric2",
			MetricData3: "test-metric3",
		},
	)
	if err != nil {
		log.Println("RequestCommittee failed", err)
	} else {
		log.Println("RequestCommittee ACK:", ack)
	}

	// final. LeaveNetwork API를 호출해 mesh network에서 탈퇴
	/* _, err := c.LeaveNetwork(context.Background(),
		&pb.NodeAccount{NodeId: "node1"})
	if err != nil {
		log.Fatalf("LeaveNetwork error")
	} */
}
