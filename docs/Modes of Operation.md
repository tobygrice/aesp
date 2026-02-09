AES describes how to encrypt one 16-byte block, with no mention of how to handle plaintext longer than 16 bytes. This is where modes of operation come in. There are several, but the following were considered for my project.

## ECB Mode
Electronic Codebook (ECB) mode is the easiest to implement, and the least secure. You simply encrypt the plaintext in 16 byte blocks and combine them to form the output. This is fine on very small inputs, but becomes highly problematic on large inputs where course-grained patterns are visible. The example below highlights this.

![[Pasted image 20260209105425.png]]
https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation

## CBC Mode
Cipher block chaining (CBC) mode is the simplest solution to the insecurity presented by ECB. Each block of plaintext is simply XORed with the previous ciphertext block, then encrypted. The first block is XORed with an initialisation vector (IV).

This means that each ciphertext block depends on all plaintext blocks that appear before it. This solves the pattern issue in ECB, but means that the encryption **must** be run serially. 

## CTR Mode
Counter (CTR) mode turns AES from a block cipher to a stream cipher. You start with a counter = random number (nonce) then increment it for each new block.
You then encrypt the *counter*, and XOR the result with the plaintext to produce the ciphertext. The diagram below explains this perfectly.

![[Pasted image 20260209110711.png]]
https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation

