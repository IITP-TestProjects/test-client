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

func main() {
	nodeID := flag.String("node", "node1", "node ID to subscribe. -node=<nodeID>")
	flag.Parse()

	if err := runClient(*nodeID); err != nil {
		log.Fatal(err)
	}
}

func runClient(nodeID string) error {
	//grpc.Dial하는 함수의 경우, docker기반 테스트 환경이므로 해당 container명 기입함.
	conn, err := grpc.NewClient("interface-server1:50051",
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	client := pb.NewMeshClient(conn)

	//실제 구독 시작
	if err := subscribe(client, nodeID); err != nil {
		return err
	}

	select {}
}

func subscribe(c pb.MeshClient, nodeID string) error {
	stream, err := c.JoinNetwork(context.Background(),
		&pb.NodeAccount{NodeId: nodeID})
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
					&pb.NodeAccount{NodeId: nodeID})
				return
			}
		}
	}()
	return nil
}

func o1Scenario(c pb.MeshClient) error {
	// 1. JoinNetwork API를 호출해 CEF를 subscribe
	_, err := c.JoinNetwork(context.Background(),
		&pb.NodeAccount{NodeId: "node1"})
	if err != nil {
		return err
	}

	// 2. Server로 Request를 보내 서명압축에 필요한 정보와 자신을 식별할 수 있는 ID를 전송
	// 이후 과정은 서버에서 진행 및 JoinNetwork로 연결한 Subscribe channel로 정보가 내려옴.

	// final. LeaveNetwork API를 호출해 mesh network에서 탈퇴
	_, err = c.LeaveNetwork(context.Background(),
		&pb.NodeAccount{NodeId: "node1"})
	if err != nil {
		return err
	}
	return nil
}
