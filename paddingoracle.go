package main

import (
	"crypto/aes"
	"crypto/rand"
	"fmt"
	"io"
)

type paddingOracleFunc func(ciphertext []byte) bool

func main() {

	key := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(err)
	}

	ciphertext := encrypt(key, []byte("This is a really long secret string that is probably very hard to guess"))

	oracle := getPaddingOracle(key)
	solution := solveMessage(oracle, ciphertext)

	fmt.Printf("decrypted string: %s\n", solution)
}

/**
Iterate over blocks and solve each one. The first block is assumed to be the IV.
**/
func solveMessage(oracle paddingOracleFunc, ciphertext []byte) []byte {

	numBlocks := len(ciphertext) / aes.BlockSize
	solution := make([]byte, len(ciphertext)-aes.BlockSize)

	for block := 0; block < numBlocks-1; block++ {
		start := block * aes.BlockSize
		end := start + (aes.BlockSize * 2)
		ciphertextTry := ciphertext[start:end]

		fuzzingBlock := make([]byte, aes.BlockSize)

		var psize int
		var solvedByte byte

		for i := 0; i < aes.BlockSize; i++ {
			solvedByte, fuzzingBlock, psize = solvePosition(oracle, ciphertextTry, fuzzingBlock, i)
			solution[(block*aes.BlockSize)+aes.BlockSize-1-i] = solvedByte

			fuzzingBlock = getNextFuzzingBlock(fuzzingBlock, i+2, psize)
		}

	}

	return solution
}

/**
Suppose we solve the last byte in the ciphertext. We have a fuzzingBlock that produces
a valid padding when decrypted. Usually this means that the last byte is byte(01). Now to
solve the second block, we need a fuzzing block that decrypts such that the last byte is byte(02).
**/
func getNextFuzzingBlock(block []byte, position int, lastPadSize int) []byte {

	out := make([]byte, aes.BlockSize)
	copy(out, block)
	for i := aes.BlockSize - 1; i > aes.BlockSize-position; i-- {
		out[i] = out[i] ^ byte(lastPadSize) ^ byte(position)
	}

	return out
}

/**
Given a fuzzingBlock, it will try to find the plaintext at target[position]. This is done by
fuzzing the byte at that position and check if the padding oracle says the padding is valid.
**/
func solvePosition(oracle paddingOracleFunc, ciphertext []byte, fuzzingBlock []byte, position int) (byte, []byte, int) {
	blocks := getBlocks(ciphertext, aes.BlockSize)

	part1 := blocks[0]
	part2 := blocks[1]

	var paddingSize = -1

	out := make([]byte, aes.BlockSize)
	copy(out, fuzzingBlock)

	var solvedByte byte

	for i := 0; i < 256; i++ {
		out[aes.BlockSize-position-1] = byte(i) ^ part1[aes.BlockSize-position-1]

		ciphertextTry := joinBlocks(out, part2)

		if !oracle(ciphertextTry) {
			continue
		}

		paddingSize = findPaddingSize(oracle, ciphertextTry, position)

		if paddingSize == -1 {
			panic("Incorrect padding. Cannot decrypt.")
		}
		solvedByte = byte(paddingSize) ^ byte(i)
		break
	}

	return solvedByte, out, paddingSize
}

/**
Set up the padding oracle that the attacker can call.
**/
func getPaddingOracle(key []byte) paddingOracleFunc {
	return func(ciphertext []byte) bool {
		out, _ := decrypt(key, ciphertext)

		return isValidPad(out)
	}
}

/**
Given a fuzzed ciphertext which decrypts to a valid padding, find the padding size.
For example:
[.... 01] = 1
[.... 02 02] = 2
[.... 03 02 01] 1
The test is done by iteratively fuzzing from the start, modifying bytes and checking when the padding becomes invalid.
**/
func findPaddingSize(oracle paddingOracleFunc, ciphertext []byte, position int) int {

	blocks := getBlocks(ciphertext, aes.BlockSize)

	//iv := blocks[0]
	part1 := blocks[0]
	part2 := blocks[1]

	fuzzingBlock := make([]byte, aes.BlockSize)

	var n = -1

	for i := 0; i < aes.BlockSize; i++ {
		copy(fuzzingBlock, part1)
		fuzzingBlock[i] = fuzzingBlock[i] ^ 0xff

		ciphertextTry := joinBlocks(fuzzingBlock, part2)

		if !oracle(ciphertextTry) {
			n = aes.BlockSize - i
			break
		}
	}

	return n

}

func joinBlocks(blocks ...[]byte) []byte {
	out := make([]byte, 0)

	for _, block := range blocks {
		out = append(out, block...)
	}

	return out
}

func getBlocks(in []byte, blocksize int) [][]byte {
	out := make([][]byte, 0)

	for i := 0; i < len(in); i = i + blocksize {
		out = append(out, in[i:i+blocksize])
	}

	return out
}

func isValidPad(in []byte) bool {
	if len(in) == 0 {
		return false
	}

	padding := in[len(in)-1]
	if int(padding) > len(in) || padding > aes.BlockSize {
		return false
	} else if padding == 0 {
		return false
	}

	for i := len(in) - 1; i > len(in)-int(padding)-1; i-- {
		if in[i] != padding {
			return false
		}
	}
	return true
}
