// Package rsa_test test rsa utility functions.
package rsa_test

import (
	"testing"
	"fmt"
	"github.com/nethatix/rsa"
)


func TestReverseRsaEnc(t *testing.T) {
	// public key (n, e)
	var n, e int64 = 937513, 638471

	// original number
	var messageToEnc int64 = 888888
	fmt.Printf("n: %v e: %v original number: %v\n", n, e, messageToEnc)

	// encrypt original_number
	cipher := rsa.GetEncOrDecMsg(messageToEnc, e, n)
	fmt.Println("cipher = ", cipher)
	mPrime := rsa.DecryptCipher(cipher, n, e)
	if messageToEnc != mPrime {
		fmt.Printf("Decrypted message %v not matching original %v\n", mPrime, messageToEnc)
		t.Errorf("Decrypted message %v not matching original %v\n", mPrime, messageToEnc)
	} else {
		fmt.Printf("Decrypted message matches original. Success breaking rsa encryption for public key n: %v e: %v", n, e)
	}
}
