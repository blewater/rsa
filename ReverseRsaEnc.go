// Package rsa contains simple exploration of the math concepts
// behind RSA encryption & decryption
package rsa

import "fmt"

// GetGcd calculates the greatest common divisor
// or highest common factor (hcf) of 2 numbers.
func GetGcd(n1, n2 int) int {

	for n1%n2 != 0 {
		n1, n2 = n2, n1%n2
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
func GetPrimeFactors(n int) (int, int) {

	xFixed := 2
	cycleSize := 2
	x := 2
	factor := 1

	for factor == 1 {
		count := 1
		for count <= cycleSize && factor <= 1 {
			x = (x*x + 1) % n
			factor = GetGcd(x-xFixed, n)
			count++
		}
		cycleSize *= 2
		xFixed = x
	}

	p := factor
	q := n //factor
	fmt.Println("p: ", p, ", q: ", q)
	return p, q
}

// getPhi calculates Phi(n) as phi = (p-1)*(q-1)
func getPhi(p, q int) int {

	phi := (p - 1) * (q - 1)
	fmt.Println("Phi: ", phi)

	return phi
}

// GetExtEuclideanAlgorithm returns (gcd, x, y) such that
// a * x + b * y == gcd, where gcd is the greatest
// common divisor of a and b.
// https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
func GetExtEuclideanAlgorithm(a, b int) (int, int, int) {

	s, old_s := 0, 1
	t, old_t := 1, 0
	r, old_r := b, a

	for r != 0 {
		quotient := old_r // r
		old_r, r = r, old_r-quotient*r
		old_s, s = s, old_s-quotient*s
		old_t, t = t, old_t-quotient*t
	}

	gcd, x, y := old_r, old_s, old_t

	return gcd, x, y
}

// GetMultInverse returns the multiplicative inverse of
// n modulo p.
// This function returns an integer m such that
// (n * m) % p == 1.
func GetMultInverse(n, modulusBase int) (int, error) {

	gcd, x, _ := GetExtEuclideanAlgorithm(n, modulusBase)

	if gcd != 1 {
		return 0, fmt.Errorf("GetMultInverse: no inverse is found because gcd is not 1 but %v. n is 0 (%v), or modulusBase (%v) is not a prime number", gcd, n, modulusBase)
	}
	return x % modulusBase, nil
}

// GetEncOrDecMsg calculates a ** power % number
// https://stackoverflow.com/questions/8496182/calculating-powa-b-mod-n
func GetEncOrDecMsg(base, exp, modulus int) int {

	base %= modulus
	result := 1
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
func DecryptCipher(cipher, n, e int) int {

	p, q := GetPrimeFactors(n)
	phi := getPhi(p, q)
	d, err := GetMultInverse(e, phi)
	if err != nil {
		fmt.Println(e)
	}
	fmt.Println("d = ", d)
	m := GetEncOrDecMsg(cipher, d, n)

	return m
}
