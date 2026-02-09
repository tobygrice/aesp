AES is a 16-byte block cipher, meaning it encrypts 16-byte blocks of plaintext at a time. It can operate using a 128, 192, or 256 bit key, which correspond to 10, 12, and 14 encryption rounds respectively.

Encryption runs as follows.
1. `KeyExpansion` - round keys are derived from the original key using the [[Key Schedule]]. A 128-bit key is derived for each encryption round. 
2. Initial round key addition:
    1. `AddRoundKey` – each byte of the state is XORed with the first round key (the first 128 bits of the original key)
3. 9, 11 or 13 rounds (corresponding to key size):
    1. `SubBytes` - bytes are substituted using the [[Constants#SBOX|SBOX|]].
    2. `ShiftRows` - each row of the state is shifted
    3. `MixColumns` - combines/mixes the four bytes of each column
    4. `AddRoundKey` - xor corresponding round key with state
4. Final round (10, 12 or 14 rounds in total):
    1. `SubBytes`
    2. `ShiftRows`
    3. `AddRoundKey`

### AddRoundKey
Bitwise xor of each byte in the current round key with the state.

### SubBytes
Each byte in the state is substituted using the [[Constants#SBOX|SBOX|]], a table of constants.
- `state[i] = SBOX[state[i]]`

## MixColumns
This step is more complicated. Each column of the state is multiplied by a constant matrix in the Galois finite field. 

![[Pasted image 20260209112750.png]]
How the resultant state column $b$ is computed from the original state column $a$ (https://en.wikipedia.org/wiki/Advanced_Encryption_Standard).

This can be expressed as follows:
![[Pasted image 20260209112910.png]]
https://en.wikipedia.org/wiki/Rijndael_MixColumns

Note that this multiplication occurs in the Galois finite field. This comprises two steps:
1. the two polynomials that represent the bytes are multiplied as polynomials
2. the resulting polynomial is reduced modulo the following fixed polynomial: 
$$m(x) = x^8 + x^4 + x^3 + x + 1$$
https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf

[Wikipedia](https://en.wikipedia.org/wiki/Rijndael_MixColumns) provides substitution tables for GF multiplication by these numbers, but this requires 6 256-byte lookup tables (9, 11, 13, and 14 are required for decryption).
