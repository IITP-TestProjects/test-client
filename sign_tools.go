package main

import (
	"crypto/sha512"
	"log"
	"test-client/golang-x-crypto/ed25519"
	"test-client/golang-x-crypto/ed25519/cosi"
	pb "test-client/proto_interface"
	"time"

	vrfed "github.com/yoseplee/vrf/edwards25519"
)

func (t *transferServer) verifyRosterHash(aggregatedSign []byte) bool {
	//roster hash를 이용한 공개키 명시적 증명
	// 1) rosterHash' = SHA-256(sort_lex(compress(pubKeys))...)
	pkBytes := make([][]byte, 0, len(t.cosignContext.publicKeys))
	for _, pk := range t.cosignContext.publicKeys {
		b := make([]byte, len(pk))
		copy(b, pk)
		pkBytes = append(pkBytes, b)
	}
	rosterHashPrime := computeRosterHash(pkBytes)

	// 2) m' = bindMessage(m || rosterHash')
	boundMsgPrime := bindMessage(testMsg, rosterHashPrime)

	// 3) aggregatedSign에서 R,S 분리
	if len(aggregatedSign) < 64 {
		log.Println("aggregatedSign too short for R,S")
		return false
	}
	R := aggregatedSign[:32]
	S := aggregatedSign[32:64]

	// 4) c = ScReduce(SHA-512(R || A || m'))
	//    A는 합성 공개키(압축 32B)로 전달받은 것을 사용
	if len(t.cosignContext.aggPubKey) != 32 {
		log.Println("invalid aggregated public key size")
		return false
	}
	var aggK [32]byte
	copy(aggK[:], t.cosignContext.aggPubKey)

	h := sha512.New()
	h.Write(R)
	h.Write(aggK[:])
	h.Write(boundMsgPrime)
	var digest [64]byte
	h.Sum(digest[:0])

	var cReduced [32]byte
	vrfed.ScReduce(&cReduced, &digest)

	// 5) s.B == R + c.A 확인 (표준 Ed25519 검증식)
	var A vrfed.ExtendedGroupElement
	if !A.FromBytes(&aggK) {
		log.Println("failed to decompress aggregated public key")
		return false
	}
	// R = s*B - c*A  =>  compute s*B + (-c)*A
	vrfed.FeNeg(&A.X, &A.X)
	vrfed.FeNeg(&A.T, &A.T)

	var projR vrfed.ProjectiveGroupElement
	var sScalar [32]byte
	copy(sScalar[:], S)
	vrfed.GeDoubleScalarMultVartime(&projR, &cReduced, &A, &sScalar)

	var checkR [32]byte
	projR.ToBytes(&checkR)
	if subtleConstantTimeCompare(R, checkR[:]) != 1 {
		log.Println("roster-hash bound verification failed: sB != R + cA")
		return false
	} else {
		log.Println("roster-hash bound verification succeeded")
		return true
	}
}

// local constant-time compare to avoid importing crypto/subtle into this file twice.
func subtleConstantTimeCompare(a, b []byte) int {
	if len(a) != len(b) {
		return 0
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	if v == 0 {
		return 1
	}
	return 0
}

func verifySignature(cosignContext *cosignContext, aggregatedSign []byte) bool {
	//log.Println("Aggregated Signature: ", aggregatedSign)
	log.Printf("aggSign: %x\n", aggregatedSign)
	log.Printf("Size of aggSign: %d Bytes\n", len(aggregatedSign))
	log.Println("--------------Start Verify--------------")
	start := time.Now()
	boundMsg := bindMessage(testMsg, cosignContext.rosterHash)
	ok := cosi.Verify(cosignContext.publicKeys, nil, boundMsg, aggregatedSign)
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

	// rosterHash는 서버가 내려주면 우선 사용, 없으면 PublicKeys로 계산
	rh := msg.RosterHash
	if len(rh) == 0 {
		log.Println("compute rosterHash from PublicKeys")
		rh = computeRosterHash(msg.PublicKeys)
	}

	// 커밋값이 정해진 상태에서 커밋값을 사용
	t.cosignContext = &cosignContext{
		publicKeys: pubKeys,
		aggPubKey:  msg.AggregatedPubKey,
		rosterHash: rh,
	}
}
