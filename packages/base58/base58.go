package base58

import (
	"github.com/pkg/errors"
	"math/big"
)

const alphabet = "C23456789rB1ZEFGTtYiAaVvMmHUPWXKDNbcdefghLjkSnopRqsJuQwxyz"

var byteToAlphabet = map[byte]uint64{49: 11, 50: 1, 51: 2, 52: 3, 53: 4, 54: 5, 55: 6, 56: 7, 57: 8, 65: 20, 66: 10, 67: 0, 68: 32, 69: 13, 70: 14, 71: 15, 72: 26, 74: 51, 75: 31, 76: 41, 77: 24, 78: 33, 80: 28, 81: 53, 82: 48, 83: 44, 84: 16, 85: 27, 86: 22, 87: 29, 88: 30, 89: 18, 90: 12, 97: 21, 98: 34, 99: 35, 100: 36, 101: 37, 102: 38, 103: 39, 104: 40, 105: 19, 106: 42, 107: 43, 109: 25, 110: 45, 111: 46, 112: 47, 113: 49, 114: 9, 115: 50, 116: 17, 117: 52, 118: 23, 119: 54, 120: 55, 121: 56, 122: 57}

// Encode encodes a byte slice to a modified base58 string.
func Encode(digest []byte) (string, error) {
	if len(digest) == 9 {
		encodedHead, _ := Encode(digest[:1])
		encodedBody, _ := Encode(digest[1:])
		return encodedHead + encodedBody, nil
	}

	if len(digest) != 1 && len(digest) != 8 {
		return "", errors.New("Invalid digest length given, must be 1, 8 or 9 bytes long")
	}

	var bigRadix = big.NewInt(58)
	var bigHelper = big.NewInt(256)
	var bigZero = big.NewInt(0)

	value := big.NewInt(0)
	numValues := big.NewInt(1)
	for i := len(digest) - 1; i >= 0; i-- {
		octet := new(big.Int).Mul(big.NewInt(int64(digest[i])), numValues)
		value = new(big.Int).Add(value, octet)
		numValues = new(big.Int).Mul(numValues, bigHelper)
	}

	characterValues := []int64{}
	for numValues.Cmp(bigZero) > 0 {
		mod := new(big.Int)
		value.DivMod(value, bigRadix, mod)
		characterValues = append(characterValues, mod.Int64())
		numValues = numValues.Div(numValues, bigRadix)
	}
	var characters []byte
	for i := len(characterValues) - 1; i >= 0; i-- {
		characters = append(characters, alphabet[characterValues[i]])
	}

	return string(characters), nil
}

func Decode(code string) ([]byte, error) {
	n := len(code)
	var bitLength uint8
	switch n {
	case 13:
		decodedHead, err := Decode(code[:2])
		if err != nil {
			return nil, err
		}
		decodedBody, err := Decode(code[2:])
		if err != nil {
			return nil, err
		}
		return append(decodedHead, decodedBody...), nil

	case 2:
		bitLength = uint8(8)
	case 11:
		bitLength = uint8(64)
	default:
		return nil, errors.Errorf("Code must be 2, 11, or 13 chars. Not %d", n)
	}
	value := uint64(0)
	numvalues := uint64(1)
	counter := 0
	for i := n - 1; i >= 0; i-- {
		value += byteToAlphabet[byte(code[i])] * numvalues
		numvalues *= 58
		counter += 1
	}

	data := make([]byte, bitLength/8)
	for i := len(data) - 1; i >= 0; i-- {
		data[i] = byte(value % 256)
		value /= 256
	}
	return data, nil
}
