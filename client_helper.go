package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"log"
	"math/big"

	vrfs "test-client/vrfs"
)

const sortitionThreshold = 1.0

func generateKeys() (ed25519.PublicKey, ed25519.PrivateKey) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal("Error generating key pair: ", err)
	}

	return pk, sk
}

func hashRatio(vrfOutput []byte) float64 {
	t := &big.Int{}
	t.SetBytes(vrfOutput[:])

	precision := uint(8 * (len(vrfOutput) + 1))
	max, b, err := big.ParseFloat("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 0, precision, big.ToNearestEven)
	if b != 16 || err != nil {
		log.Fatal("failed to parse big float constant for sortition")
	}

	//hash value as int expression.
	//hval, _ := h.Float64() to get the value
	h := big.Float{}
	h.SetPrec(precision)
	h.SetInt(t)
	//https://stackoverflow.com/questions/13582519/how-to-generate-hash-number-of-a-string-in-go
	ratio := big.Float{}
	cratio, _ := ratio.Quo(&h, max).Float64()

	return cratio
}

func isSelected(ratio float64) bool {
	fmt.Println(ratio)
	if ratio > sortitionThreshold {
		return false
	}
	return true
}

func generateVrfOutput(
	seed string,
	pubKey ed25519.PublicKey,
	secKey ed25519.PrivateKey) []byte {
	msg := sha256.Sum256([]byte(fmt.Sprintf("%s", seed)))

	pi, vrfOutput, err := vrfs.Prove(pubKey, secKey, msg[:])
	if err != nil {
		log.Fatal(err)
	}
	res, err := vrfs.Verify(pubKey, pi, msg[:])
	if err != nil {
		log.Fatal(err)
	}
	if !res {
		log.Println("Error res")
	}

	ratio := hashRatio(vrfOutput)
	//현재 threshold를 1.0으로 설정했으므로 모든 노드가 선출됨.
	sortitionResult := isSelected(ratio)

	log.Println("EXECUTING_VRF_RATIO_RESULT: ", ratio, sortitionResult)

	if sortitionResult == true {
		return pi
	} else {
		return nil
	}
}
