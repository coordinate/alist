package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	// "github.com/CrackedPoly/AES-implementation-in-Golang/src/aes"
)

type AesCTR struct {
	password      string
	sizeSalt      string
	passwdOutward string
	key           []byte
	iv            []byte
	soureIv       []byte
	cipher        cipher.Stream
}

const MAX_UINT32 = 0xffffffff

func NewAesCTR(password string, sizeSalt int) (*AesCTR, error) {
	ac := &AesCTR{
		password: password,
		sizeSalt: fmt.Sprintf("%d", sizeSalt),
	}

	// Check base64
	// if len(password) != 32 {
	// 	salt := []byte("AES-CTR") // The salt used in the original Node.js code
	// 	iterations := 1000        // The number of iterations
	// 	keyLength := 16           // Desired key length in bytes
	// 	// Generate the PBKDF2 key
	// 	key := pbkdf2.Key([]byte(password), salt, iterations, keyLength, sha256.New)
	// 	// Convert the key to a hex string
	// 	ac.passwdOutward = hex.EncodeToString(key)
	// }
	ac.passwdOutward = "1957a5abbad658aaae6d3a38ce66f5f2"

	// Create AES-CTR key
	passwdSalt := ac.passwdOutward + ac.sizeSalt
	hashMD5 := md5Sum(passwdSalt)
	ac.key = hashMD5[:16] // AES-128 requires a 16-byte key
	ac.iv = md5Sum(ac.sizeSalt)[:16]

	// Copy to soureIv
	ac.soureIv = make([]byte, len(ac.iv))
	copy(ac.soureIv, ac.iv)
	return ac, nil
}

func md5Sum(str string) []byte {
	checksum := md5.Sum([]byte(str))
	return checksum[0:]
}

// func md5Sum(data string) []byte {
// 	h := md5.New()
// 	h.Write([]byte(data))
// 	return h.Sum(nil)
// }

func (ac *AesCTR) createCipher() error {
	block, err := aes.NewCipher(ac.key)
	if err != nil {
		return err
	}
	ac.cipher = cipher.NewCTR(block, ac.iv)
	return nil
}

func (ac *AesCTR) Encrypt(message []byte) []byte {
	if ac.cipher == nil {
		ac.createCipher()
	}
	out := make([]byte, len(message))
	ac.cipher.XORKeyStream(out, message)
	return out
}

func (ac *AesCTR) Decrypt(message []byte) []byte {
	return ac.Encrypt(message) // Decryption is the same as encryption in CTR mode
}

func (ac *AesCTR) SetPosition(position int) {
	ac.iv = make([]byte, len(ac.soureIv))
	copy(ac.iv, ac.soureIv)

	increment := position / 16
	ac.incrementIV(uint32(increment))

	ac.createCipher()

	offset := position % 16
	buffer := make([]byte, offset)
	ac.Encrypt(buffer) // To advance the stream
}

func (ac *AesCTR) incrementIV(increment uint32) {
	incrementBig := increment / MAX_UINT32
	incrementLittle := increment % MAX_UINT32

	// split the 128 bits IV in 4 numbers, 32 bits each
	overflow := uint32(0)
	for idx := 0; idx < 4; idx++ {
		num := binary.BigEndian.Uint32(ac.iv[12-idx*4 : 16-idx*4])
		incValue := overflow
		if idx == 0 {
			incValue += incrementLittle
		}
		if idx == 1 {
			incValue += incrementBig
		}
		num += incValue

		numBig := num / MAX_UINT32
		numLittle := num % MAX_UINT32
		overflow = numBig
		binary.BigEndian.PutUint32(ac.iv[12-idx*4:16-idx*4], numLittle)
	}
}

// func (ac *AesCTR) incrementIV(increment int) {
// 	const maxUint32 = 0xffffffff
// 	incrementBig := increment / maxUint32
// 	incrementLittle := increment % maxUint32

// 	// Split the 128 bits IV into 4 numbers, 32 bits each
// 	overflow := 0
// 	for i := 0; i < 4; i++ {
// 		num := binary.BigEndian.Uint32(ac.iv[12-4*i : 16-4*i])
// 		inc := overflow
// 		if i == 0 {
// 			inc += incrementLittle
// 		}
// 		if i == 1 {
// 			inc += incrementBig
// 		}
// 		num += uint32(inc)
// 		overflow = int(num >> 32)
// 		binary.BigEndian.PutUint32(ac.iv[12-4*i:16-4*i], uint32(num))
// 	}
// }

// func DecryptAES128CTR(key []byte, iv []byte, ciphertext []byte) ([]byte, error) {
// 	// // Create a new AES cipher
// 	// block, err := aes.NewCipher(key)
// 	// if err != nil {
// 	// 	return nil, err
// 	// }
// 	// // Create a new CTR stream
// 	// stream := cipher.NewCTR(block, iv)
// 	// // Create a buffer to hold the decrypted data
// 	// plaintext := make([]byte, len(ciphertext))
// 	// // XOR the ciphertext with the stream to decrypt
// 	// stream.XORKeyStream(plaintext, ciphertext)
// 	// return plaintext, nil
// 	_aes, err := aes.NewAES(key)
// 	if err != nil {
// 		fmt.Printf("%s", err)
// 		return nil, err
// 	}
// 	plaintext := _aes.EncryptCTR(ciphertext, iv)
// 	return plaintext, nil
// }
