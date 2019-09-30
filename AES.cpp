// Reads key and message from standard input. Encrypts with 128 bit AES encryption.
// Outputs ciphertext to standard output.

#include <stdint.h>
#include <iostream>

#define BYTE unsigned char
#define ROTL8(x,shift) ((uint8_t) ((x) << (shift)) | ((x) >> (8 - (shift))))

using namespace std;

const uint8_t keySize = 16;
const uint8_t blockSize = 16;
const uint8_t rounds = 10;
const uint8_t rowSize = blockSize / 4;
const uint8_t rcon[] = {0x01,	0x02,	0x04,	0x08,	0x10,
												0x20,	0x40,	0x80,	0x1B,	0x36};

// Algorithm for genenrating s_box
// Derived from Advanced Encryption Standard 2001 specification
// https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf
void InitializeSbox(uint8_t s_box[]) {
	uint8_t p = 1;
	uint8_t q = 1;

	// loop invariant: p * q == 1 in the Galois field
	do {
		// multiply p by 3
		p = p ^ (p << 1) ^ (p & 0x80 ? 0x1B : 0);

		// divide q by 3 (equals multiplication by 0xf6)
		q ^= q << 1;
		q ^= q << 2;
		q ^= q << 4;
		q ^= q & 0x80 ? 0x09 : 0;

		// compute the affine transformation
		uint8_t xformed = q ^ ROTL8(q, 1) ^ ROTL8(q, 2) ^ ROTL8(q, 3) ^ ROTL8(q, 4);

		s_box[p] = xformed ^ 0x63;
	} while (p != 1);

	// 0 has no inverse
	s_box[0] = 0x63;
}

// Algorithm for genenrating Galois matrix multiplication tables and
// modifying columns
// Derived from Advanced Encryption Standard 2001 specification
// https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf
void MultiplyColumn(BYTE col[]) {
	// 'ones' is a copy of input column
	// 'twos' is the elements multiplied by 2 in Rijndael's Galois field
	// ones[n] ^ twos[n] is element n multiplied by 3 in Rijndael's Galois field
  BYTE ones[rowSize];
  BYTE twos[rowSize];
  for (BYTE i = 0; i < rowSize; i++) {
      ones[i] = col[i];
      // high_bit is 0xff if the high bit of col[n] is 1, 0 otherwise */
			// arithmetic right shift, shifting in zeros or ones
			BYTE high_bit = (BYTE)((signed char)col[i] >> 7);
			// remove high bit because twos[i] is an 8-bit char
			// so we xor by 0x1b and not 0x11b
      twos[i] = col[i] << 1;
      twos[i] ^= 0x1B & high_bit;
  }
	// Rijndael's Galois field
	// 2*x0 + 3*x1 + x3 + x2
  col[0] = twos[0] ^ ones[3] ^ ones[2] ^ twos[1] ^ ones[1];
	// x0 + 2*x1 + 3*x2 + x3
  col[1] = twos[1] ^ ones[0] ^ ones[3] ^ twos[2] ^ ones[2];
	// x0 + x1 + 2*x2 + 3*x3
  col[2] = twos[2] ^ ones[1] ^ ones[0] ^ twos[3] ^ ones[3];
	// 3*x0 + x1 + x2 + 2*x3
  col[3] = twos[3] ^ ones[2] ^ ones[1] ^ twos[0] ^ ones[0];
}

// Multiply columns of block by Galois matrix
void MixColumns(BYTE state[]) {
	for (int i = 0; i < blockSize; i += rowSize) {
		MultiplyColumn(state + i);
	}
}

// Perform key expansion
void ExpandKey(BYTE key[], BYTE expanded_keys[], uint8_t s_box[]) {
	// Copy first key
	for (int i = 0; i < keySize; i++) {
		expanded_keys[i] = key[i];
	}

	// Keep track of total bytes and rcon
	int total_bytes = 16;
	int rcon_index = 1;

	// temp word for xor
	BYTE temp[rowSize];

	while (total_bytes < (keySize * (rounds + 1))) {
		// Grab prev 4 bytes for core
		for (int i = 0; i < rowSize; i++) {
			temp[i] = expanded_keys[total_bytes - rowSize + i];
		}

		// Perform key schedule once every 16 bytes
		if (total_bytes % blockSize == 0) {
			// Rotate left
			BYTE first = temp[0];
			for (int i = 0; i < rowSize - 1; i++) {
				temp[i] = temp[i + 1];
			}
			temp[rowSize - 1] = first;

			// substitute bytes
			for (int i = 0; i < rowSize; i++) {
				temp[i] = s_box[temp[i]];
			}

			// XOR with rcon value
			temp[0] ^= rcon[rcon_index - 1];
			rcon_index++;
		}

		// XOR temp with first 4 bytes of previous key
		for (int i = 0; i < rowSize; i++) {
			expanded_keys[total_bytes] = expanded_keys[total_bytes - 16] ^ temp[i];
			total_bytes++;
		}
	}
}

// Substitute bytes from s box
void SubBytes(BYTE state[], uint8_t s_box[]) {
	for (int i = 0; i < blockSize; i++) {
		state[i] = s_box[state[i]];
	}
}

// Shift rows left
void ShiftRows(BYTE state[]) {
	// Loops is too confusing in 1D and it is only a 4x4 matrix so
	// we go manually

	// fill temp array
	BYTE temp[blockSize];
	temp[0] = state[0];
	temp[1] = state[5];
	temp[2] = state[10];
	temp[3] = state[15];
	temp[4] = state[4];
	temp[5] = state[9];
	temp[6] = state[14];
	temp[7] = state[3];
	temp[8] = state[8];
	temp[9] = state[13];
	temp[10] = state[2];
	temp[11] = state[7];
	temp[12] = state[12];
	temp[13] = state[1];
	temp[14] = state[6];
	temp[15] = state[11];

	// copy back to state
	for (int i = 0; i < blockSize; i++) {
		state[i] = temp[i];
	}
}

void AddRoundKey(BYTE state[], BYTE round_key[]) {
	for (int i = 0; i < blockSize; i++) {
		state[i] ^= round_key[i];
	}
}

// Perform AES encryption on given block
void Encrypt(BYTE block[], BYTE cipher_text[], BYTE expanded_keys[], uint8_t s_box[]) {
	// copy block to state
	BYTE state[blockSize];
	for (int i = 0; i < blockSize; i++) {
		state[i] = block[i];
	}

	// inital round
	AddRoundKey(state, expanded_keys);
	int key_index = keySize;

	// 9 main rounds
	for (int i = 0; i < rounds - 1; i++) {
		SubBytes(state, s_box);
		ShiftRows(state);
		MixColumns(state);
		AddRoundKey(state, expanded_keys + key_index);
		key_index += keySize;
	}

	// final round
	SubBytes(state, s_box);
	ShiftRows(state);
	AddRoundKey(state, expanded_keys + key_index);

	// copy to cipher_text array
	for (int i = 0; i < blockSize; i++) {
		cipher_text[i] = state[i];
	}
}

int main(int argv, char **argc) {
	// Generate s-box
	uint8_t s_box[256];
	InitializeSbox(s_box);

	// Read key
  BYTE key[keySize];
	for (int i = 0; i < keySize; i++) {
		char temp;
		std::cin.get(temp);
		key[i] = temp;
	}

	// Expand key
	BYTE expanded_keys[(rounds + 1) * keySize];
	ExpandKey(key, expanded_keys, s_box);

	// Read blocks
	char temp;
	while (std::cin.get(temp)) {
		BYTE block[blockSize];
		block[0] = temp;
		for (int i = 1; i < blockSize; i++) {
			std::cin.get(temp);
			block[i] = temp;
		}

		// Encrypt blocks
		BYTE cipher_text[blockSize];
		Encrypt(block, cipher_text, expanded_keys, s_box);

		// Print cipher text
		for (int i = 0; i < blockSize; i++) {
			std::cout.put(cipher_text[i]);
		}
	}

	return 0;
}
