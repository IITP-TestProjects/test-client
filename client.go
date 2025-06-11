package main

import (
	"bytes"
	"context"
	"crypto/sha512"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	cpb "test-client/proto_client"
	pb "test-client/proto_interface"

	"test-client/golang-x-crypto/ed25519/cosi"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var global_node_num int

func main() {
	nodeId := flag.String("nodeid", "node1", "node ID to subscribe. -node=<nodeId>")
	serverAddress := flag.String("server", "interface-server1:50051", "--server=<serverIP>:<port>")
	primaryAddress := flag.String("primary", "client1:50052", "--primary=<serverIP>:<port>")
	nodeNum := flag.Int("nodenum", 10, "number of nodes in the network. -nodenum=<node_num>")
	flag.Parse()

	global_node_num = *nodeNum

	ts := &transferServer{}

	if *nodeId == "node1" {
		go func() {
			startClientGrpcServer(ts)
		}()
		// 서버가 포트 바인딩을 완료할 시간을 주기 위해 잠시 대기
		time.Sleep(200 * time.Millisecond)
	} else {
		time.Sleep(400 * time.Millisecond) // 다른 노드들은 잠시 대기
	}

	if err := runClient(*nodeId, ts, *serverAddress, *primaryAddress); err != nil {
		log.Fatal(err)
	}
}

func runClient(
	nodeId string, ts *transferServer, serverAddr string, primaryAddress string) error {
	//grpc.Dial하는 함수의 경우, docker기반 테스트 환경이므로 해당 container명 기입함.
	conn, err := grpc.NewClient(serverAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	priCon, err := grpc.NewClient(primaryAddress,
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatal(err)
	}
	defer priCon.Close()

	client := pb.NewMeshClient(conn)
	priCli := cpb.NewTransferSignClient(priCon)

	//실제 구독 시작
	ts.subscribe(client, priCli, nodeId)
	if nodeId != "node1" {
		ts.subscribeDoneSignal(priCli, nodeId)
	}

	publicKey, secretKey = generateKeys()
	ts.wait = make(chan struct{})

	if nodeId != "node1" {
		<-ts.wait
		time.Sleep(1 * time.Second)
	} else {
		for {
			ts.mu.Lock()
			ready := len(ts.subs) >= global_node_num-1
			ts.mu.Unlock()
			if ready {
				break
			}
			time.Sleep(500 * time.Millisecond)
			log.Println("check! subs:", len(ts.subs))
		}
		ts.broadcast(&cpb.InternalBroadcastData{Round: 0})
	}
	legacySignScenario(nodeId, ts, priCli)
	log.Println("start scenario")
	for {
		aggregateSignScenario(client, nodeId)
		<-ts.wait
		ts.wait = make(chan struct{})
		time.Sleep(4 * time.Second) // 4초 대기 후 다음 라운드 시작
		round++
		log.Printf("Round %d started!\n", round)
	}
}

// O(1)만에 검증가능한 sign 시연 시나리오
func aggregateSignScenario(c pb.MeshClient, nodeId string) {
	// 1. JoinNetwork API를 호출해 CEF를 subscribe (매번 다른 seed 생성)
	//subscribe(c, nodeId, ts)
	seed := fmt.Sprintf("round-%d-node-%s", round, nodeId)

	// 2. vrf 실행(커미티 선정된 상태면 실행필요 x)
	vrfProof := generateVrfOutput(seed, publicKey, secretKey)

	// 3. schnorr에 사용할 nonce commit생성, secretR은 서명 시 사용(보관)
	// -> secretR과 짝인 commit은 매 라운드마다 생성되어야함.
	var err error
	var commit cosi.Commitment

	hash := sha512.Sum512([]byte(seed))
	reader := bytes.NewReader(hash[:])
	commit, secretR, err = cosi.Commit(reader)
	if err != nil {
		log.Fatalln(err)
	}

	// 4. Server로 Request를 보내 서명압축에 필요한 정보와 자신을 식별할 수 있는 ID를 전송
	// 이후 과정은 서버에서 진행 및 연결한 Subscribe channel로 정보가 내려옴.
	if round == 0 {
		resCommittee, err := c.RequestCommittee(context.Background(),
			&pb.CommitteeCandidateInfo{
				Round:  round,
				NodeId: nodeId,

				Seed:      seed,
				Proof:     vrfProof,
				PublicKey: publicKey,
				Commit:    commit,

				MetricData1: "test-metric1",
				MetricData2: "test-metric2",
				MetricData3: "test-metric3",
			},
		)
		//false가 반환된 경우라면 해당 노드는 이미 프로세스가 시작되었으므로 라운드에 참여 못했다는 뜻.
		if !resCommittee.Ok {
			log.Println("I didn't candidate node", nodeId)
			os.Exit(0)
		}
		if err != nil {
			log.Println("RequestCommittee failed", err)
		}
	} else {
		//log.Println("send RequestAggreegatedCommit")
		_, err = c.RequestAggregatedCommit(context.Background(),
			&pb.CommitData{
				Round:  round,
				Commit: commit,
			},
		)
		if err != nil {
			log.Println("RequestAggreegatedCommit failed", err)
		}
	}

	// final. LeaveNetwork API를 호출해 mesh network에서 탈퇴
	/* _, err := c.LeaveNetwork(context.Background(),
		&pb.NodeAccount{NodeId: "node1"})
	if err != nil {
		log.Fatalf("LeaveNetwork error")
	} */
}
