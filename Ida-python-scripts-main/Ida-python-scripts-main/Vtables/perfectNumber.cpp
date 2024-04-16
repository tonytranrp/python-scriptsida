#include <iostream>
#include <cmath>


bool isPrime(long long num) {
    if (num <= 1) return false;
    if (num <= 3) return true;
    if (num % 2 == 0 || num % 3 == 0) return false;

    for (long long i = 5; i * i <= num; i += 6) {
        if (num % i == 0 || num % (i + 2) == 0) {
            return false;
        }
    }
    return true;
}

void generateMersennePrimes(int n) {
    int count = 0;
    long long mersenneExp = 2;
    while (count < n) {
        long long mersenneNum = pow(2, mersenneExp) - 1;
        if (isPrime(mersenneNum)) {
            std::cout << "Mersenne Prime #" << ++count << ": " << mersenneNum << std::endl;
        }
        mersenneExp++;
    }
}

int main() {
    int n;
    std::cout << "Enter the number of Mersenne primes to generate: ";
    std::cin >> n;
    std::cout << "Generating Mersenne primes..." << std::endl;
    generateMersennePrimes(n);
    return 0;
}
