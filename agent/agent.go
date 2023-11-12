package main

import (
	"fmt"
	"log"
	"os"

	"crypto/sha256"
	"golang.org/x/crypto/ssh"
)

func main() {
	// User must authenticate to agent
	// Once user authenticates, agent needs to get the private key
	key, err := os.ReadFile("../../listofkeys/id_test")
	if err != nil {
		log.Fatal("Failed to load private key: ", err)
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		log.Fatal("Failed to parse prviate key: ", err)
	}

	pub := signer.PublicKey().Marshal()
	hash := sha256.Sum256([]byte(pub))

	fmt.Printf("hash: %v", hash[:])

}
