#AES Encryption

###Input
Standard input consists of a key to use, followed by one or more blocks to encrypt using that key.

The 128-bit key is given as the first 16 bytes of the file. The first byte gives the first 8 bits, and so on.

Each block consists of exactly 16 bytes. There are at most 106 blocks to encrypt.

In the example input file, the key written in hexadecimal is F4C020A0A1F604FD343FAC6A7E6AE0F9, and the only block to encrypt is F295B9318B994434D93D98A4E449AFD8.

###Output
Standard output should contain, for each block, the encryption of that block, in the same format as the input.

The output for the example above, written in hexadecimal, is 52E418CBB1BE4949308B381691B109FE.
