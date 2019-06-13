// Package rsa contains simple exploration of the math concepts
// behind RSA encryption & decryption
package rsa

import (
	"fmt"
	"math/big"
)

// Modulus in contrast to go's native % modulus operator (sign matches the dividend's)
// returns only positive remainder results
// and in contrast to python's modulus operator which sign matches the divisor's.
// Overriding the default go's sign result allows the GetPrimeFactors below
// to calculate accurate factors.
// https://en.wikipedia.org/wiki/Modulo_operation
// https://stackoverflow.com/questions/43018206/modulo-of-negative-integers-in-go
func Modulus(d, m int64) int64 {
	res := d % m
	if res < 0 && m > 0 {
		return res + m
	}
	return res
}

// GetGcd calculates the greatest common divisor
// or highest common factor (hcf) of 2 numbers.
// Overriding bigInt's gcd because of bigInt's modulus behavior.
func GetGcd(n1, n2 int64) int64 {

	for n1%n2 != 0 {
		n1, n2 = n2, Modulus(n1, n2)
	}
	return n2
}

// GetPrimeFactors is an implementation of
// Pollard’s Rho Algorithm which is a
// a probabilistic algorithmic implementation of
// integer factorization of a composite number. In this context
// we attempt to break RSA's N number to its 2 prime factors
// so we may recreate the private key.
// https://en.wikipedia.org/wiki/Pollard's_rho_algorithm
func GetPrimeFactors(n int64) (int64, int64) {

	xFixed := big.NewInt(2)
	tempX := big.NewInt(2)
	cycleSize := 2
	x := big.NewInt(2)
	var factor int64 = 1
	oneBig := big.NewInt(1)
	nBig := big.NewInt(int64(n))

	for factor == 1 {
		for count := 1; count <= cycleSize && factor <= 1; count++ {
			x.Mul(x, x)
			x.Add(x, oneBig)
			x.Mod(x, nBig) // x = (x*x + 1) % n
			tempX.Sub(x, xFixed)
			tempXint64 := tempX.Int64()
			factor = GetGcd(tempXint64, n)
			//fmt.Printf(", x: %v, xFixed: %v, tempX: %v, tempXint64: %v, factor: %v\n", x, xFixed, tempX, tempXint64, factor)
		}
		cycleSize *= 2
		//fmt.Printf(" ,cycleSize: %v", cycleSize)
		xFixed.Set(x)
	}

	p := factor
	q := n / p
	fmt.Println("p: ", p, ", q: ", q)
	return p, q
}

// getPhi calculates Phi(n) as phi = (p-1)*(q-1)
func getPhi(p, q int64) int64 {

	phi := (p - 1) * (q - 1)
	fmt.Println("Phi: ", phi)

	return phi
}

// simpleModularInverse calculates the multiplicative inverse of num (i) so that num*i = 1 mod n.
// A simple but specific only for cases that modular inverse exists GCD = 1
// otherwise it loops forever.
func simpleModularInverse(num, modBase int64) int64 {
	var i int64 = 1

	for i%num > 0 {
		i += modBase
	}
	return i / num
}

// GetExtEuclideanAlgorithm returns (gcd, x, y) such that
// a * x + b * y == gcd, where gcd is the greatest
// common divisor of a and b.
// https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
func GetExtEuclideanAlgorithm(a, b int64) (int64, int64, int64) {

	var s, prvS int64 = 0, 1
	var t, prvT int64 = 1, 0
	var r, oldR int64 = b, a
	var quotient int64

	for r != 0 {
		quotient = oldR / r
		oldR, r = r, oldR-quotient*r
		prvS, s = s, prvS-quotient*s
		prvT, t = t, prvT-quotient*t
	}

	gcd, x, y := oldR, prvS, prvT

	return gcd, x, y
}

// GetMultInverse returns the multiplicative inverse of
// n modulo p.
// This function returns an integer m such that
// (n * m) % p == 1.
func GetMultInverse(n, modulusBase int64) (int64, error) {

	gcd, x, _ := GetExtEuclideanAlgorithm(n, modulusBase)

	if gcd != 1 {
		return 0, fmt.Errorf("GetMultInverse: no inverse is found because gcd is not 1 but %v. n is 0 (%v), or modulusBase (%v) is not a prime number", gcd, n, modulusBase)
	}
	return x % modulusBase, nil
}

// GetEncOrDecMsg calculates a ** power % number
// https://stackoverflow.com/questions/8496182/calculating-powa-b-mod-n
func GetEncOrDecMsg(base, exp, modulus int64) int64 {

	base %= modulus
	var result int64 = 1
	for exp > 0 {
		if (exp & 1) > 0 {
			result = (result * base) % modulus
		}
		base = (base * base) % modulus
		exp >>= 1
	}
	return result
}

// DecryptCipher converts an encrypted number c = m (mod n)
// into the original m = (e)^c d (mod n),
// where 0 < m < n is some integer.
func DecryptCipher(cipher, n, e int64) int64 {

	p, q := GetPrimeFactors(n)
	phi := getPhi(p, q)
	d, err := GetMultInverse(e, phi)
	if err != nil {
		fmt.Println(e)
	}
	// Riskier alternative for calculating inverse
	// d := simpleModularInverse(e, phi)
	fmt.Println("d = ", d)
	m := GetEncOrDecMsg(cipher, d, n)

	return m
}
