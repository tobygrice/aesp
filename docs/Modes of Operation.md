AES describes how to encrypt one 16-byte block, with no mention of how to handle plaintext longer than 16 bytes. This is where modes of operation come in. There are several, but the following were considered for my project.

## ECB Mode
Electronic Codebook (ECB) mode is the easiest to implement, and the least secure. You simply encrypt the plaintext in 16 byte blocks and combine them to form the output. This is fine on very small inputs, but becomes highly problematic on large inputs where course-grained patterns are visible. The example below highlights this.

![[Pasted image 20260209105425.png]]
https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation

## CBC Mode
Cipher block chaining (CBC) mode is the simplest solution to the insecurity presented by ECB. Each block of plaintext is simply XORed with the previous ciphertext block, then encrypted. The first block is XORed with an initialisation vector (IV).

This means that each ciphertext block depends on all plaintext blocks that appear before it. This solves the pattern issue in ECB, but means that the encryption **must** be run serially. 

## CTR Mode
Counter (CTR) mode turns AES from a block cipher to a stream cipher. You add an incrementing counter to an initialisation vector and encrypt the *counter*, not the plaintext. You then xor the encrypted counter block with a block of the plaintext to produce a block of ciphertext. So long as the IV+ctr block you encrypt is never reused, this remains cryptographically secure.

The diagram below illustrates this perfectly.

![[Pasted image 20260209110711.png]]
https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation

The biggest challenge here is deciding on nonce/counter sizes. Most commonly, a 96 bit nonce/IV is used with a 32-bit counter. This gives $2^{32}$ unique values for counter, meaning a limit of $2^{32}$ blocks can be encrypted using that nonce. $2^{32}$ 16-byte blocks is exactly 64 GiB of data. Whilst large enough for most uses, it is not uncommon that one may wish to encrypt more than 64 GiB of data. 

This is why I considered a 64-bit nonce with a 64-bit counter. This is less commonly used, but allows for $2^{64}$ blocks to be encrypted, or roughly 262,000 petabytes of data -> essentially no practical limit on encryption input size. However, it also means less bits are available for the nonce, increasing the odds of a nonce being reused. They are still very small, but much smaller than a 96 bit nonce.

I decided to implement a 32-bit counter / 96-bit nonce. Most implementations only encrypt in a certain chunk size (e.g. 64 KiB), then generate a new IV.