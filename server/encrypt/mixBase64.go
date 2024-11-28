package encrypt

import (
	"crypto/sha256"
	"math/rand"
	"strings"
	"time"
)

const source = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~+"

func initKSA(passwd string) string {
	var key []byte
	if len(passwd) > 0 {
		hash := sha256.Sum256([]byte(passwd))
		key = hash[:]
	}

	sbox := make([]int, len(source))
	K := make([]byte, len(source))

	// Initialize S table
	for i := range sbox {
		sbox[i] = i
	}

	// Fill K table with the key
	for i := range K {
		K[i] = key[i%len(key)]
	}

	// Permute the S table
	j := 0
	for i := range sbox {
		j = (j + sbox[i] + int(K[i])) % len(source)
		sbox[i], sbox[j] = sbox[j], sbox[i]
	}

	var secret strings.Builder
	for _, i := range sbox {
		secret.WriteByte(source[i])
	}
	return secret.String()
}

// MixBase64 structure
type MixBase64 struct {
	chars    []byte
	mapChars map[byte]int
}

func NewMixBase64(passwd string, salt string) *MixBase64 {
	secret := passwd
	if len(passwd) != 64 {
		secret = initKSA(passwd + salt)
	}
	chars := []byte(secret)

	// Create mapping of characters
	mapChars := make(map[byte]int)
	for i, e := range chars {
		mapChars[e] = i
	}

	return &MixBase64{
		chars:    chars,
		mapChars: mapChars,
	}
}

// Encode method
func (m *MixBase64) Encode(data []byte) string {
	var result strings.Builder
	for i := 0; i < len(data); i += 3 {
		var bt []byte
		if i+3 > len(data) {
			bt = data[i:]
		} else {
			bt = data[i : i+3]
		}

		switch len(bt) {
		case 1:
			result.WriteByte(m.chars[bt[0]>>2])
			result.WriteByte(m.chars[(bt[0]&3)<<4])
			result.WriteString("==")
		case 2:
			result.WriteByte(m.chars[bt[0]>>2])
			result.WriteByte(m.chars[(bt[0]&3)<<4|bt[1]>>4])
			result.WriteByte(m.chars[(bt[1]&15)<<2])
			result.WriteByte('=')
		default:
			result.WriteByte(m.chars[bt[0]>>2])
			result.WriteByte(m.chars[(bt[0]&3)<<4|bt[1]>>4])
			result.WriteByte(m.chars[(bt[1]&15)<<2|bt[2]>>6])
			result.WriteByte(m.chars[bt[2]&63])
		}
	}
	return result.String()
}

// Decode method
func (m *MixBase64) Decode(base64Str string) ([]byte, error) {
	// Calculate size
	size := (len(base64Str) / 4) * 3
	if strings.Contains(base64Str, string(m.chars[64])+string(m.chars[64])) {
		size -= 2
	} else if strings.Contains(base64Str, string(m.chars[64])) {
		size -= 1
	}
	buffer := make([]byte, size)

	var j int
	for i := 0; i < len(base64Str); i += 4 {
		enc1 := m.mapChars[base64Str[i]]
		enc2 := m.mapChars[base64Str[i+1]]
		enc3 := m.mapChars[base64Str[i+2]]
		enc4 := m.mapChars[base64Str[i+3]]

		buffer[j] = byte((enc1 << 2) | (enc2 >> 4))
		j++
		if enc3 < 64 {
			buffer[j] = byte(((enc2 & 15) << 4) | (enc3 >> 2))
			j++
		}
		if enc4 < 64 {
			buffer[j] = byte(((enc3 & 3) << 6) | enc4)
			j++
		}
	}
	return buffer, nil
}

// CheckBit function
func GetCheckBit(text string) byte {
	var count int
	for _, num := range []byte(text) {
		count += int(num)
	}
	count %= 64
	return source[count]
}

// RandomSecret function
func RandomSecret() string {
	rand.Seed(time.Now().UnixNano())
	chars := []byte(source)
	var newChars []byte
	for len(chars) > 0 {
		index := rand.Intn(len(chars))
		newChars = append(newChars, chars[index])
		chars = append(chars[:index], chars[index+1:]...)
	}
	return string(newChars)
}

// RandomStr function
func RandomStr(length int) string {
	rand.Seed(time.Now().UnixNano())
	chars := []byte(source)
	var newChars []byte
	for length > 0 {
		index := rand.Intn(len(chars))
		newChars = append(newChars, chars[index])
		chars = append(chars[:index], chars[index+1:]...)
		length--
	}
	return string(newChars)
}

// GetSourceChar function
func GetSourceChar(index byte) byte {
	return source[index]
}
