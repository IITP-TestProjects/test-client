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
			log.Printf("[Received] %s: %q", msg.Origin, string(msg.Data))
			messageCount++

			//메시지를 10번초과로 수신한 경우, LeaveNetwork API를 호출해 graceful-shutdown
			if messageCount > 10 {
				c.LeaveNetwork(context.Background(),
					&pb.NodeAccount{NodeId: nodeID})
			}
		}
	}()
	return nil
}
