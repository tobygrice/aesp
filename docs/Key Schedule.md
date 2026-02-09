The AES key schedule converts the key sizes into the following number of 128-bit round keys.
- 128-bit key -> 10 round keys
- 192-bit key -> 12 round keys
- 256-bit key -> 14 round keys

The key expansion algorithm is best described using a diagram:

![[Pasted image 20260209113841.png]]
https://en.wikipedia.org/wiki/AES_key_schedule#/media/File:AES-Key_Schedule_128-bit_key.svg


**Rotate Words (RotWord)**
`RotWord` is a one-byte left circular shift:
$$\text{RotWord} ([b_0, b_1, b_2, b_3]) = [b_1, b_2, b_3, b_0]$$

**SubWord**
`SubWord` just substitutes each byte in the word with the [[Constants#SBOX|SBOX]].

**RCON**
[[Constants#RCON|RCON]] (round constant) is just a constant that is XORed with the word of the corresponding round. Only the first byte of the four byte word has bits set, so we only need to store that byte. 

RCON, SubWord, and RotWord can calculated in a single line very easily:
```rust
temp = [
	SBOX[temp[1] as usize] ^ RCON[round],
	SBOX[temp[2] as usize],
	SBOX[temp[3] as usize],
	SBOX[temp[0] as usize],
];
```

FIPS-197 provides the following pseudocode:
```
procedure KEYEXPANSION(key)
	i ← 0
	while i ≤ Nk −1 do
		w[i] ← key[4 ∗ i..4 ∗ i+3]
		i ← i+1
	end while // When the loop concludes, i = Nk.
	while i ≤ 4 ∗ Nr +3 do
		temp ← w[i−1]
		if i mod Nk = 0 then
			temp ← SUBWORD(ROTWORD(temp)) ⊕ Rcon[i/Nk]
		else if Nk > 6 and i mod Nk = 4 then
			temp ← SUBWORD(temp)
		end if
		w[i] ← w[i−Nk] ⊕ temp
		i ← i+1
	end while
	return w
end procedure 
```
https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf


