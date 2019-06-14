// Package rsa contains simple exploration of the math concepts
// behind RSA encryption & decryption.
// There's usage of Pollard's Rho factorization method to reverse simple encryption keys.
package rsa

import (
	"fmt"
	"math/big"
)

// EuclideanMod in contrast to go's native % modulus operator (sign matches the dividend's)
// returns only positive remainder results according to the Euclidean definition
// in which the remainder is nonnegative always, 0 ≤ r, and is thus consistent
// with the Euclidean division algorithm to produce correct results when used
// with the [Extended] Euclidean algorithms for number inversions.
// Overriding the default go's sign result allows the GetPrimeFactors below
// to calculate accurate factors.
// https://en.wikipedia.org/wiki/Modulo_operation
// https://stackoverflow.com/questions/43018206/modulo-of-negative-integers-in-go
// func EuclideanMod(d, m int64) int64 {
// 	res := d % m
// 	if res < 0 && m > 0 {
// 		return res + m
// 	}
// 	return res
// }

// EuclideanMod in contrast to go's native % modulus operator (sign matches the dividend's)
// returns only positive remainder results according to the Euclidean definition
// in which the remainder is nonnegative always, 0 ≤ r, and is thus consistent
// with the Euclidean division algorithm to produce correct results when used
// with the [Extended] Euclidean algorithms for number inversions.
// Overriding the default go's sign result allows the GetPrimeFactors below
// to calculate accurate factors.
// https://en.wikipedia.org/wiki/Modulo_operation
// https://stackoverflow.com/questions/43018206/modulo-of-negative-integers-in-go
func EuclideanMod(d, m int64) int64 {

	// fmt.Println("d: ", d, ", m: ", m, ", zero: ", zero)
	res := d & m

	//fmt.Println("res: ", res)
	if res < -1 && m > 0 {
		return res + m
	}
	return res
}

// GetMod is applying Euclidean Modulus to math/big integers
// without side effects.
func GetMod(n1, n2 big.Int) big.Int {

	// Clone and perform modulus to avoid mutation.
	res := new(big.Int).Mod(&n1, &n2)

	return *res
}

// GetGcd calculates the greatest common divisor
// or highest common factor (hcf) of 2 numbers without side effects.
// Overriding bigInt's gcd because of bigInt's modulus behavior.
func GetGcd(n1, n2 big.Int) *big.Int {

	zero := big.NewInt(0)

	// Clone to avoid side effects to the caller's args.
	n1Copy := new(big.Int).Set(&n1)
	n2Copy := new(big.Int).Set(&n2)
	//fmt.Printf("Starting..n1: %v, n2: %v, n1n2Mod: %v\n", n1Copy, n2Copy, GetMod(*n1Copy, *n2Copy))

	for n1n2Mod := GetMod(*n1Copy, *n2Copy); n1n2Mod.Cmp(zero) != 0; {
		n1Copy.Set(n2Copy)
		//fmt.Printf("n1: %v, n2: %v, n1n2Mod: %v\n", n1Copy, n2Copy, &n1n2Mod)
		n2Copy.Set(&n1n2Mod)
		//fmt.Printf("n1: %v, n2: %v, n1n2Mod: %v\n", n1Copy, n2Copy, &n1n2Mod)
		n1n2Mod = GetMod(*n1Copy, *n2Copy)
		//fmt.Printf("n1: %v, n2: %v, n1n2Mod: %v\n", n1Copy, n2Copy, &n1n2Mod)
	}
	return n2Copy
}

// GetPrimeFactors is an implementation of
// Pollard’s Rho Algorithm which is a
// a probabilistic algorithmic implementation of
// integer factorization of a composite number. In this context
// we attempt to break RSA's N number to its 2 prime factors
// so we may recreate the private key.
// https://en.wikipedia.org/wiki/Pollard's_rho_algorithm
func GetPrimeFactors(n int64) (big.Int, big.Int) {

	xFixed := big.NewInt(2)
	tempX := big.NewInt(2)
	cycleSize := 2
	x := big.NewInt(2)
	factor := big.NewInt(1)
	one := big.NewInt(1)
	nBig := big.NewInt(n)

	for factor.Cmp(one) == 0 {
		for count := 1; count <= cycleSize && factor.Cmp(one) <= 0; count++ {
			x.Mul(x, x)
			x.Add(x, one)
			x.Mod(x, nBig) // x = (x*x + 1) % n
			tempX.Sub(x, xFixed)
			//fmt.Printf("tempX: %v, x: %v, xFixed: %v\n", tempX, x, xFixed)
			factor = GetGcd(*tempX, *nBig)
			// fmt.Printf(", x: %v, xFixed: %v, tempX: %v, factor: %v\n", x, xFixed, tempX, factor)
		}
		cycleSize *= 2
		//fmt.Printf(" ,cycleSize: %v\n", cycleSize)
		xFixed.Set(x)
	}

	p := factor
	q := nBig.Div(nBig, p)
	fmt.Println("p: ", p, ", q: ", q)
	return *p, *q
}

// GetPhi calculates Phi(n) as phi = (p-1)*(q-1)
// with big.Int without side effects.
func GetPhi(p, q big.Int) *big.Int {

	pCopy := new(big.Int).Set(&p)
	qCopy := new(big.Int).Set(&q)
	one := big.NewInt(1)

	pCopy = pCopy.Sub(pCopy, one)
	qCopy = qCopy.Sub(qCopy, one)

	phi := pCopy.Mul(pCopy, qCopy)
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
		return 0, fmt.Errorf("GetMultInverse: no inverse is found either because gcd is not 1 but %v, or n is 0 (%v), or modulusBase (%v) is not a prime number", gcd, n, modulusBase)
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
	phi := GetPhi(p, q)
	d, err := GetMultInverse(e, phi.Int64())
	if err != nil {
		fmt.Println(e)
	}
	// Riskier alternative for calculating inverse
	// d := simpleModularInverse(e, phi)
	fmt.Println("d = ", d)
	m := GetEncOrDecMsg(cipher, d, n)

	return m
}
