package encrypt

type CRCn struct {
	table        []byte
	initialValue byte
}

// CRC8 Polynomial values
var POLY8 = struct {
	CRC8              byte
	CRC8_CCITT        byte
	CRC8_DALLAS_MAXIM byte
	CRC8_SAE_J1850    byte
	CRC_8_WCDMA       byte
}{
	CRC8:              0xd5,
	CRC8_CCITT:        0x07,
	CRC8_DALLAS_MAXIM: 0x31,
	CRC8_SAE_J1850:    0x1d,
	CRC_8_WCDMA:       0x9b,
}

// ****************************************************

// Constructor for CRCn
func NewCRCn(num int, polynomial byte, initialValue byte) *CRCn {
	if polynomial == 0 {
		polynomial = POLY8.CRC8_DALLAS_MAXIM
	}

	crc := &CRCn{initialValue: initialValue}
	if num == 6 {
		crc.table = crc.generateTable6()
	} else if num == 8 {
		crc.table = crc.generateTable8MAXIM(polynomial)
	}
	return crc
}

// Calculate the checksum
func (crc *CRCn) Checksum(byteArray []byte) byte {
	c := crc.initialValue
	for _, b := range byteArray {
		c = crc.table[int(c^b)]
	}
	return c
}

// Generate CRC8 lookup table
// func (crc *CRCn) generateTable8(polynomial byte) []byte {
// 	csTable := make([]byte, 256)
// 	for i := 0; i < 256; i++ {
// 		curr := byte(i)
// 		for j := 0; j < 8; j++ {
// 			if (curr & 0x80) != 0 {
// 				curr = (curr << 1) ^ polynomial
// 			} else {
// 				curr <<= 1
// 			}
// 		}
// 		csTable[i] = curr
// 	}
// 	return csTable
// }

// Generate CRC8 Dallas Maxim table
func (crc *CRCn) generateTable8MAXIM(_ byte) []byte {
	csTable := make([]byte, 256)
	for i := 0; i < 256; i++ {
		curr := byte(i)
		for j := 0; j < 8; j++ {
			if (curr & 0x01) != 0 {
				curr = (curr >> 1) ^ 0x8C
			} else {
				curr >>= 1
			}
		}
		csTable[i] = curr
	}
	return csTable
}

// Generate CRC6 table
func (crc *CRCn) generateTable6() []byte {
	csTable := make([]byte, 256)
	for i := 0; i < 256; i++ {
		curr := byte(i)
		for j := 0; j < 8; j++ {
			if (curr & 0x01) != 0 {
				curr = (curr >> 1) ^ 0x30
			} else {
				curr >>= 1
			}
		}
		csTable[i] = curr
	}
	return csTable
}

// ****************************************************
