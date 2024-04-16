#include <iostream>
#include <cmath>

bool isPrime(int n) {
    if (n <= 1) return false;
    if (n <= 3) return true;
    if (n % 2 == 0 || n % 3 == 0) return false;
    for (int i = 5; i * i <= n; i += 6) {
        if (n % i == 0 || n % (i + 2) == 0) return false;
    }
    return true;
}

bool isMersennePrime(int p) {
    int exponent = log2(p + 1);
    return (1 << exponent) == (p + 1) && isPrime(exponent);
}

int main() {
    int maxPrime = 100000; // Maximum prime number to search for Mersenne primes
    std::cout << "Mersenne Primes up to " << maxPrime << ":" << std::endl;

    for (int p = 2; p <= maxPrime; ++p) {
        if (isMersennePrime(p)) {
            std::cout << p << " ";
        }
    }

    return 0;
}
