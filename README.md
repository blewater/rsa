# RSA #

## RSA is likely the most popular public key cryptographic set of algorithms. ##

Step 1:
Choose two secret large random primes `p, q`.

Step 2:
Compute `p*q = n.` n is disclosed as part of the public key.

Step 3:
Compute `Phi(n) = (p-1)*(q-1).` This is the totient function answering the number of co-prime numbers between 1...n.

Step 4:
Choose a number `e < n` which is co-prime to Phi(n).

`(n, e) is then the public key.`

Step 5:
Find the modular multiplicative inverse of e modulo Phi(n) `e` such that `e*d ≡ 1 (mod Phi(n)).`

`(n, d) is then the private key.`

Step 6:
Encrypt a message `m` such that `cipher = m^e(mod n).`

Step 7:
Decrypt an encrypted message cipher such that `m = cipher^d(mod n).`

#### Question 1: ####
Why is deriving the private d from (n, e) extremely challenging for large secret random p, q prime factors?

#### Answer: ####
While there has been progress in factoring at least one large n number up to 193 digits (RSA-640 bits,) cracking 1024-bit numbers or even as large as 2048-bit numbers appear to out of reach for the time being.

#### Question 2: ####
Does that mean that RSA is uncrackable for large n (> 2048 bits)?

#### Answer 2: ####
Yes, if the chosen random p, q primes are truly random and truly primes which has not always been the case commercially.

``` Note: there is a known exploit for cracking large keys by pairing same-sized n public RSA keys and calculating hcf on them to find any factors other than 1. If one is computed (poor p, q randomness) it is likely a prime factor of both n and the 2nd factor can then be instantly computed instantly.```

[Pollard's Rho](https://www.wikiwand.com/en/Pollard%27s_rho_algorithm) is a relatively efficient probabilistic algorithm for factoring small sized n. 

The Rho algorithm is employed to reverse an encrypted RSA message in this repo.



