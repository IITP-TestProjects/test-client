# Blockchain/Client Node Mock

CEF 연동 테스트를 위한 블록체인 클라이언트 노드 모의 구현

## 프로젝트 개요

이 repository는 IITP 과제 「노드 간 메시지 전달과 합의를 위한 최적 경로 네트워크 프로토콜 기술개발」의 committee election 테스트 환경을 구성하기 위한 blockchain/client node mock 구현이다.

현재 코드 기준으로 이 repository는 실제 운영용 blockchain node가 아니라, CEF middleware와 연동하는 blockchain/client node mock이다. 각 client node는 CEF의 `mesh.Mesh` gRPC service에 접속해 committee candidate 정보와 Schnorr signing commitment를 전송하고, CEF가 `JoinNetwork` stream으로 broadcast하는 `FinalizedCommittee`를 수신한다.

또한 이 repository 내부에는 client mock들 사이의 partial signature 수집을 위한 별도 gRPC service인 `transfer_sign.TransferSign`이 있다. 이 내부 service는 CEF public API가 아니라, 테스트 client node 중 primary 역할을 하는 `node1`이 다른 client mock들로부터 partial signature와 legacy signature를 모으기 위해 사용한다.

CEF, verify node, MongoDB 구현 세부사항은 이 repository에 포함되어 있지 않으며, 본 repository는 CEF와 연동되는 blockchain/client node mock의 동작만 다룬다.

## 전체 IITP Committee Election 테스트 구성에서의 역할

전체 테스트 시스템은 다음 세 구성요소로 구성된다.

1. `CEF-server`
   - 구성: CEF Interface Server + MongoDB Replica Set
   - 역할: blockchain/client node와 verify node 사이에서 gRPC 기반 committee election middleware 역할 수행
   - CEF gRPC server port: `50051`
   - MongoDB replica set: `mongo1`, `mongo2`, `mongo3` / `rs0`
   - candidate/node history 저장

2. `IITP-TestProjects/test-verifynode`
   - 역할: CEF가 전달한 committee candidate 목록을 검증/선정하고 committee result를 반환하는 verify node mock
   - gRPC service: `committee.CommitteeService`
   - 주요 RPC: `RequestCommittee(CommitteeRequest) returns (CommitteeInfo)`
   - 테스트 구성에서 CEF는 `-verifynode=verify-server1:50053` 형태로 이 node에 접속한다.

3. `IITP-TestProjects/test-client`
   - 이 repository
   - 역할: CEF에 committee candidate 정보와 Schnorr signing commitment를 전송하고, CEF가 broadcast하는 committee 결과를 수신하는 blockchain/client node mock
   - CEF의 `mesh.Mesh` gRPC service에 client로 접속한다.
   - 내부적으로 `node1`은 `transfer_sign.TransferSign` gRPC server를 열어 다른 mock client들의 partial signature를 수집한다.

이 repository는 verify node와 직접 통신하지 않는다. Verify node 호출은 CEF middleware가 담당한다.

## 시스템 아키텍처

테스트 실행 시 각 client process는 같은 binary를 실행하되 `--nodeid` 값으로 역할을 구분한다.

- 모든 node는 CEF `mesh.Mesh` service에 `--server` 주소로 접속한다.
- 모든 node는 `JoinNetwork` stream을 열고 `FinalizedCommittee` broadcast를 수신한다.
- `node1`은 내부 primary node처럼 동작하며 `:50052`에서 `transfer_sign.TransferSign` gRPC server를 실행한다.
- `node2` 이후 node들은 `--primary` 주소로 `node1`에 접속해 내부 round 완료 신호와 partial signature 전달에 사용한다.
- round 0에서는 `RequestCommittee`로 candidate 정보를 CEF에 보낸다.
- round 1 이후에는 `RequestAggregatedCommit`으로 round별 Schnorr signing commitment만 CEF에 보낸다.
- CEF가 `FinalizedCommittee`를 broadcast하면 각 node는 partial signature를 생성한다.
- `node1`은 committee member들의 partial signature를 모아 aggregate signature를 만들고 검증한다.

중요한 구분:

- CEF의 `mesh.Mesh` public surface에서 직접 수집하는 값은 partial signature가 아니라 `CommitteeCandidateInfo.commit` 또는 `CommitData.commit`에 담긴 Schnorr signing commitment이다.
- 이 repository에는 partial signature 생성/수집/검증 코드가 있다. 다만 이것은 `client.proto`의 `transfer_sign.TransferSign` service를 사용하는 client mock 내부 통신이다.
- `interface.proto`에는 CEF로 partial signature share를 보내는 별도 RPC가 정의되어 있지 않다.

## Repository 구조

```text
.
├── README.md
├── go.mod / go.sum
├── client.go
├── client_network.go
├── client_own_network.go
├── cosign_helper.go
├── sign_tools.go
├── legacy_sign.go
├── interface.proto
├── client.proto
├── proto_interface/
├── proto_client/
├── vrfs/
├── golang-x-crypto/
├── Dockerfile
├── docker-compose.yml
└── clientDockerBuild.sh
```

주요 파일:

- `client.go`: process entrypoint, CLI flag 정의, CEF 및 primary node 연결, round loop, `RequestCommittee` / `RequestAggregatedCommit` 호출.
- `client_network.go`: CEF `JoinNetwork` stream 구독, `FinalizedCommittee` 수신, CoSi partial signature 생성, aggregate signature 생성 helper.
- `client_own_network.go`: 내부 `transfer_sign.TransferSign` gRPC server 구현, `GetPartSign`, `GetLegacySign`, `InternalBroadcaster` 처리.
- `cosign_helper.go`: Ed25519 key 생성, VRF proof 생성, sortition threshold 처리.
- `sign_tools.go`: aggregate signature 검증, roster hash 계산/검증, `FinalizedCommittee` 기반 signing context 설정.
- `legacy_sign.go`: 비교용 legacy Ed25519 signature 생성/검증 시나리오.
- `interface.proto`: CEF `mesh.Mesh` interface 정의.
- `client.proto`: client mock 내부 `transfer_sign.TransferSign` interface 정의.
- `proto_interface/`, `proto_client/`: protobuf/gRPC generated Go code.
- `vrfs/`: VRF proof 생성/검증 구현.
- `golang-x-crypto/`: local crypto package copy. 현재 코드에서 `test-client/golang-x-crypto/ed25519/cosi`를 사용한다.
- `Dockerfile`: Go binary build 및 runtime image 구성.
- `docker-compose.yml`: 6개 client mock container 실행 구성.
- `clientDockerBuild.sh`: Docker image build helper.

## 주요 컴포넌트

### CEF Mesh client

`client.go`는 다음 flag를 정의한다.

| flag | 기본값 | 의미 |
| --- | --- | --- |
| `--nodeid` | `node1` | 현재 client mock node ID |
| `--server` | `interface-server1:50051` | CEF `mesh.Mesh` gRPC server 주소 |
| `--primary` | `client1:50052` | 내부 `transfer_sign.TransferSign` primary node 주소 |
| `--nodenum` | `10` | 테스트 network의 node 수 |

CEF 접속은 `grpc.NewClient`와 `insecure.NewCredentials()`로 수행한다. 별도 environment variable 설정 코드는 없다.

### Committee candidate 생성

`aggregateSignScenario`는 각 round에서 다음 값을 만든다.

- `seed`: `round-%d-node-%s` 형식의 문자열
- `proof`: `generateVrfOutput(seed, publicKey, secretKey)` 결과
- `publicKey`: process 시작 후 `generateKeys()`로 생성한 Ed25519 public key
- `commit`: `cosi.Commit(reader)`로 생성한 Schnorr signing commitment
- `secretR`: 위 commitment와 짝이 되는 secret nonce이며 partial signature 생성 시 사용
- `ipAddress`: `getLocalIP()`로 찾은 non-loopback IPv4 주소
- `port`: 현재 코드에서 `"50051"`로 hard-coded
- `channel`: 현재 코드에서 `"channelName"`으로 hard-coded

`cosign_helper.go`의 `sortitionThreshold`는 `1.0`으로 설정되어 있어, 현재 mock 환경에서는 사실상 모든 node가 committee candidate로 참여하는 구조에 가깝다.

### 내부 primary node와 partial signature 수집

`node1`은 `startClientGrpcServer`를 통해 TCP `:50052`에서 `transfer_sign.TransferSign` server를 실행한다.

다른 node들은 `--primary` 주소로 `node1`에 접속하고 다음 용도로 사용한다.

- `InternalBroadcaster`: round 시작/완료 동기화
- `GetLegacySign`: legacy Ed25519 signature 비교 테스트
- `GetPartSign`: CEF가 broadcast한 committee 결과를 바탕으로 생성한 partial signature 전달

`node1`은 `GetPartSign`으로 받은 `cosi.SignaturePart`들을 `committeeSize`만큼 모은 뒤 `cosigners.AggregateSignature(...)`로 aggregate signature를 만들고 `cosi.Verify(...)` 및 roster hash 기반 검증을 수행한다.

## gRPC / protobuf 인터페이스

### CEF 연동 interface: `interface.proto`

Package: `mesh`

Service: `Mesh`

```proto
rpc JoinNetwork(CommitteeCandidateInfo) returns (stream FinalizedCommittee);
rpc LeaveNetwork(NodeAccount) returns (Ack);
rpc RequestCommittee(CommitteeCandidateInfo) returns (Ack);
rpc RequestAggregatedCommit(CommitData) returns (Ack);
```

`CommitteeCandidateInfo` fields:

- `round`
- `nodeId`
- `seed`
- `proof`
- `publicKey`
- `commit`
- `ipAddress`
- `port`
- `channel`

`FinalizedCommittee` fields:

- `round`
- `channel`
- `nodeId`
- `leader_nodeId`
- `aggregatedCommit`
- `aggregatedPubKey`
- `publicKeys`
- `rosterHash`

`CommitData` fields:

- `round`
- `commit`

현재 code path에서 `LeaveNetwork` 호출은 주석 처리되어 있어 실제 실행 흐름에는 포함되지 않는다.

### Client mock 내부 interface: `client.proto`

Package: `transfer_sign`

Service: `TransferSign`

```proto
rpc GetPartSign(GetPartSignRequest) returns (Ack);
rpc GetLegacySign(GetLegacySignRequest) returns (Ack);
rpc InternalBroadcaster(InternalSubscribe) returns (stream InternalBroadcastData);
```

`GetPartSignRequest` fields:

- `nodeId`
- `round`
- `partSign`

`GetLegacySignRequest` fields:

- `message`
- `signature`
- `publicKey`

이 service는 CEF와 verify node 사이의 public interface가 아니라 이 repository의 mock client들 사이에서만 사용하는 내부 테스트 interface이다.

## 데이터 흐름

### CEF 기준 전체 흐름

1. blockchain/client node가 CEF의 `JoinNetwork` stream에 접속해 `FinalizedCommittee` 수신 채널을 연다.
2. blockchain/client node가 `RequestCommittee`로 committee candidate 정보를 CEF에 보낸다.
3. `CommitteeCandidateInfo`에는 `round`, `nodeId`, `seed`, `proof`, `publicKey`, `commit`, `ipAddress`, `port`, `channel`이 포함된다.
4. CEF는 candidate 정보를 수집하고 MongoDB에 저장한다.
5. candidate가 threshold에 도달하거나 timeout이 발생하면 CEF가 verify node의 `CommitteeService.RequestCommittee`를 호출한다.
6. CEF는 verify node에 `CommitteeRequest`를 전달한다.
7. verify node는 `CommitteeInfo`를 반환한다.
8. CEF는 선정된 committee member의 public key와 Schnorr signing commitment를 기반으로 aggregate public key와 aggregate commit을 만든다.
9. CEF는 `FinalizedCommittee`를 `JoinNetwork` stream 구독자에게 broadcast한다.
10. 이후 client node들이 `RequestAggregatedCommit`으로 round별 commit 데이터를 보내면 CEF는 다시 aggregate commit을 생성해 broadcast한다.

### 이 repository 코드 기준 실행 흐름

1. process가 시작되면 CLI flag를 읽는다.
2. `node1`이면 `:50052`에서 내부 `TransferSign` gRPC server를 시작한다.
3. 모든 node가 CEF `--server` 주소에 접속하고 `JoinNetwork(CommitteeCandidateInfo{NodeId: nodeId})` stream을 연다.
4. `node2` 이후 node들은 `--primary` 주소의 `InternalBroadcaster` stream에도 접속한다.
5. 각 node는 Ed25519 key pair를 생성한다.
6. `node1`은 내부 subscriber 수가 `--nodenum - 1`에 도달할 때까지 기다린 뒤 round 0 시작 신호를 broadcast한다.
7. legacy Ed25519 signature 비교 시나리오를 먼저 수행한다.
8. round 0에서 각 node는 VRF proof와 Schnorr signing commitment를 만들고 `RequestCommittee`를 호출한다.
9. CEF가 `FinalizedCommittee`를 보내면 각 node는 `aggregatedPubKey`, `aggregatedCommit`, `publicKeys`, `rosterHash`를 이용해 partial signature를 생성한다.
10. `node1`이 아닌 node는 partial signature를 `GetPartSign`으로 `node1`에 보낸다.
11. `node1`은 자신의 partial signature와 다른 node들의 partial signature를 모아 aggregate signature를 만들고 검증한다.
12. aggregate signature 검증이 끝나면 `node1`이 내부 broadcast로 다음 round 진행을 알린다.
13. round 1 이후 각 node는 `RequestAggregatedCommit(CommitData{Round, Commit})`을 호출한다.

## 실행 환경

- Go module: `test-client`
- `go.mod` Go version: `1.24.3`
- Dockerfile 기본 build arg:
  - `GO_VER=1.25`
  - `ALPINE_VER=3.21`
- 주요 dependency:
  - `google.golang.org/grpc`
  - `google.golang.org/protobuf`
  - `github.com/HyperspaceApp/ed25519`
  - `github.com/yoseplee/vrf`
  - `golang.org/x/crypto`
- CEF gRPC 기본 주소: `interface-server1:50051`
- 내부 primary gRPC 기본 주소: `client1:50052`
- 내부 primary listen port: `50052`
- Docker compose external network: `test-verifier_bc_interface`

## 실행 방법

### Docker image build

기존 helper script를 사용한다.

```bash
./clientDockerBuild.sh 0.1
```

위 명령은 다음 image를 만든다.

```text
bcclient:0.1
```

### Docker compose 실행

현재 `docker-compose.yml`은 `bc1`부터 `bc6`까지 6개 client mock을 실행한다.

```bash
docker compose up
```

`docker-compose.yml`은 external Docker network `test-verifier_bc_interface`가 이미 존재한다고 가정한다. CEF server compose 구성이 이 network를 만들지 않은 상태에서 단독 실행하려면 먼저 network를 만들어야 한다.

```bash
docker network create test-verifier_bc_interface
docker compose up
```

현재 compose 구성:

- `bc1`
  - container name: `client1`
  - command: `--nodeid=node1 --nodenum=6`
  - port mapping: `50052:50052`
- `bc2` ~ `bc6`
  - container name: `client2` ~ `client6`
  - command: `--nodeid=node2` ~ `--nodeid=node6`
  - `bc1`에 depends_on
- 모든 service는 `test-verifier_bc_interface` network에 연결된다.

CEF service가 같은 Docker network에서 `interface-server1:50051` 이름으로 resolve되어야 기본 설정으로 동작한다. 다른 주소를 사용하려면 각 container command에 `--server=<host>:<port>`를 추가해야 한다.

### 로컬 실행

CEF가 로컬 또는 접근 가능한 주소에서 먼저 실행 중이어야 한다.

단일 node smoke test 형태:

```bash
go run . --nodeid=node1 --nodenum=1 --server=127.0.0.1:50051 --primary=127.0.0.1:50052
```

여러 node를 로컬 process로 실행하려면 `node1`을 먼저 실행하고, 다른 terminal에서 동일한 `--primary` 주소를 바라보도록 실행한다.

```bash
go run . --nodeid=node1 --nodenum=3 --server=127.0.0.1:50051 --primary=127.0.0.1:50052
go run . --nodeid=node2 --server=127.0.0.1:50051 --primary=127.0.0.1:50052
go run . --nodeid=node3 --server=127.0.0.1:50051 --primary=127.0.0.1:50052
```

`node1`은 `--nodenum - 1`개의 내부 subscriber가 붙을 때까지 기다린다. 로컬 다중 실행에서 node 수가 맞지 않으면 `check! subs:` 로그가 반복될 수 있다.

## 설정 정보

코드에서 확인되는 설정값은 다음과 같다.

| 항목 | 값 | 위치 |
| --- | --- | --- |
| CEF server 기본 주소 | `interface-server1:50051` | `client.go` |
| 내부 primary 기본 주소 | `client1:50052` | `client.go` |
| 내부 `TransferSign` listen 주소 | `:50052` | `client_own_network.go` |
| 기본 node ID | `node1` | `client.go` |
| 기본 node 수 | `10` | `client.go` |
| compose node 수 | `6` | `docker-compose.yml` |
| candidate `Port` field | `"50051"` | `client.go` |
| candidate `Channel` field | `"channelName"` | `client.go` |
| test message | `"test message"` | `client_network.go` |
| legacy test message | `"legacy_test_message"` | `legacy_sign.go` |
| sortition threshold | `1.0` | `cosign_helper.go` |

## Troubleshooting

### `interface-server1:50051`에 접속하지 못하는 경우

CEF Interface Server가 실행 중인지, client container가 CEF와 같은 Docker network에 연결되어 있는지 확인한다. 기본 compose는 `test-verifier_bc_interface` external network를 사용한다.

### `node1`이 `check! subs:` 로그를 반복하는 경우

`--nodenum` 값과 실제 실행된 client 수가 맞지 않을 가능성이 높다. `node1`은 내부 subscriber 수가 `--nodenum - 1`이 될 때까지 round 0 시작 신호를 보내지 않는다.

### `GetPartSign failed`가 발생하는 경우

`node2` 이후 node가 `--primary` 주소로 `node1`의 `TransferSign` server에 접속하지 못한 상태이다. Docker 구성에서는 `client1:50052` 이름이 resolve되어야 한다.

### `mismatch: sig=... pubKeys=... wait` 로그가 나오는 경우

`node1`이 수집한 partial signature 수와 CEF가 내려준 `FinalizedCommittee.publicKeys` 수가 맞지 않는 상태이다. committee member 수, `FinalizedCommittee.nodeId`, `FinalizedCommittee.publicKeys`, 내부 node 실행 수를 함께 확인해야 한다.

### `RequestCommittee` 응답이 `ok=false`인 경우

코드 주석 기준으로 해당 node가 이미 시작된 process/round에 늦게 참여해 candidate로 처리되지 못한 상태로 간주하고 process를 종료한다.

### aggregate signature 검증이 실패하는 경우

다음 값을 확인한다.

- CEF가 내려준 `aggregatedPubKey`
- CEF가 내려준 `aggregatedCommit`
- CEF가 내려준 `publicKeys`
- CEF가 내려준 `rosterHash`
- client가 partial signature 생성에 사용한 `secretR`
- round별 commit과 partial signature가 같은 round의 값인지 여부
