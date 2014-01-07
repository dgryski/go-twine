// Package twine implements the TWINE lightweight block cipher
/*

http://www.nec.co.jp/rd/media/code/research/images/twine_LC11.pdf
http://jpn.nec.com/rd/crl/code/research/image/twine_SAC_full_v4.pdf
https://eprint.iacr.org/2012/422.pdf

*/
package twine

import (
	"crypto/cipher"
	"strconv"
)

type twineCipher struct {
	rk [37][8]byte // 36+1 to keep the indexes nice
}

type KeySizeError int

func (k KeySizeError) Error() string { return "twine: invalid key size " + strconv.Itoa(int(k)) }

// New returns a cipher.Block implementing the TWINE block cipher.  The key
// argument should be 10 or 16 bytes.
func New(key []byte) (cipher.Block, error) {

	l := len(key)

	if l != 10 && l != 16 {
		return nil, KeySizeError(l)
	}

	tw := &twineCipher{}

	switch l {
	case 10:
		tw.expandKeys80(key)
	case 16:
		tw.expandKeys128(key)
	}

	return tw, nil

}

func (t *twineCipher) BlockSize() int { return 8 }

func (t *twineCipher) Encrypt(dst, src []byte) {

	var x [16]byte // actually nybbles

	for i := 0; i < len(src); i++ {
		x[2*i] = src[i] >> 4
		x[2*i+1] = src[i] & 0x0f
	}

	for i := 1; i <= 35; i++ {
		for j := 0; j < 8; j++ {
			x[2*j+1] ^= sbox[x[2*j]^t.rk[i][j]]
		}

		var xnext [16]byte
		for h := 0; h < 16; h++ {
			xnext[shuf[h]] = x[h]
		}
		x = xnext
	}

	// last round
	i := 36
	for j := 0; j < 8; j++ {
		x[2*j+1] ^= sbox[x[2*j]^t.rk[i][j]]
	}

	for i := 0; i < 8; i++ {
		dst[i] = x[2*i]<<4 | x[2*i+1]
	}
}

func (t *twineCipher) Decrypt(dst, src []byte) {

	var x [16]byte // actually nybbles

	for i := 0; i < len(src); i++ {
		x[2*i] = src[i] >> 4
		x[2*i+1] = src[i] & 0x0f
	}

	for i := 36; i >= 2; i-- {
		for j := 0; j < 8; j++ {
			x[2*j+1] ^= sbox[x[2*j]^t.rk[i][j]]
		}

		var xnext [16]byte
		for h := 0; h < 16; h++ {
			xnext[shufinv[h]] = x[h]
		}
		x = xnext
	}

	// last round
	i := 1
	for j := 0; j < 8; j++ {
		x[2*j+1] ^= sbox[x[2*j]^t.rk[i][j]]
	}

	for i := 0; i < 8; i++ {
		dst[i] = x[2*i]<<4 | x[2*i+1]
	}
}

func (t *twineCipher) expandKeys80(key []byte) {

	var wk [20]byte

	for i := 0; i < len(key); i++ {
		wk[2*i] = key[i] >> 4
		wk[2*i+1] = key[i] & 0x0f
	}

	for i := 1; i <= 35; i++ {

		t.rk[i][0] = wk[1]
		t.rk[i][1] = wk[3]
		t.rk[i][2] = wk[4]
		t.rk[i][3] = wk[6]
		t.rk[i][4] = wk[13]
		t.rk[i][5] = wk[14]
		t.rk[i][6] = wk[15]
		t.rk[i][7] = wk[16]

		wk[1] ^= sbox[wk[0]]
		wk[4] ^= sbox[wk[16]]
		con := roundconst[i]
		wk[7] ^= con >> 3
		wk[19] ^= con & 7

		tmp0, tmp1, tmp2, tmp3 := wk[0], wk[1], wk[2], wk[3]
		// TODO(dgryski): replace with copy()?
		for j := 0; j < 4; j++ {
			fourj := j * 4
			wk[fourj] = wk[fourj+4]
			wk[fourj+1] = wk[fourj+5]
			wk[fourj+2] = wk[fourj+6]
			wk[fourj+3] = wk[fourj+7]
		}
		wk[16] = tmp1
		wk[17] = tmp2
		wk[18] = tmp3
		wk[19] = tmp0
	}

	t.rk[36][0] = wk[1]
	t.rk[36][1] = wk[3]
	t.rk[36][2] = wk[4]
	t.rk[36][3] = wk[6]
	t.rk[36][4] = wk[13]
	t.rk[36][5] = wk[14]
	t.rk[36][6] = wk[15]
	t.rk[36][7] = wk[16]

}

func (t *twineCipher) expandKeys128(key []byte) {

	var wk [32]byte

	for i := 0; i < len(key); i++ {
		wk[2*i] = key[i] >> 4
		wk[2*i+1] = key[i] & 0x0f
	}

	for i := 1; i <= 35; i++ {

		t.rk[i][0] = wk[2]
		t.rk[i][1] = wk[3]
		t.rk[i][2] = wk[12]
		t.rk[i][3] = wk[15]
		t.rk[i][4] = wk[17]
		t.rk[i][5] = wk[18]
		t.rk[i][6] = wk[28]
		t.rk[i][7] = wk[31]

		wk[1] ^= sbox[wk[0]]
		wk[4] ^= sbox[wk[16]]
		wk[23] ^= sbox[wk[30]]
		con := roundconst[i]
		wk[7] ^= con >> 3
		wk[19] ^= con & 7

		tmp0, tmp1, tmp2, tmp3 := wk[0], wk[1], wk[2], wk[3]
		// TODO(dgryski): replace with copy()?
		for j := 0; j < 7; j++ {
			fourj := j * 4
			wk[fourj] = wk[fourj+4]
			wk[fourj+1] = wk[fourj+5]
			wk[fourj+2] = wk[fourj+6]
			wk[fourj+3] = wk[fourj+7]
		}
		wk[28] = tmp1
		wk[29] = tmp2
		wk[30] = tmp3
		wk[31] = tmp0
	}
	t.rk[36][0] = wk[2]
	t.rk[36][1] = wk[3]
	t.rk[36][2] = wk[12]
	t.rk[36][3] = wk[15]
	t.rk[36][4] = wk[17]
	t.rk[36][5] = wk[18]
	t.rk[36][6] = wk[28]
	t.rk[36][7] = wk[31]
}

// table 1
var sbox = []byte{0x0C, 0x00, 0x0F, 0x0A, 0x02, 0x0B, 0x09, 0x05, 0x08, 0x03, 0x0D, 0x07, 0x01, 0x0E, 0x06, 0x04}

// table 2
var shuf = []int{5, 0, 1, 4, 7, 12, 3, 8, 13, 6, 9, 2, 15, 10, 11, 14}
var shufinv = []int{1, 2, 11, 6, 3, 0, 9, 4, 7, 10, 13, 14, 5, 8, 15, 12}

// table 3
var roundconst = []byte{
	0x00, // filler
	0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x03, 0x06, 0x0c, 0x18, 0x30, 0x23, 0x05, 0x0a, 0x14, 0x28, 0x13, 0x26,
	0x0f, 0x1e, 0x3c, 0x3b, 0x35, 0x29, 0x11, 0x22, 0x07, 0x0e, 0x1c, 0x38, 0x33, 0x25, 0x09, 0x12, 0x24, 0x0b,
}
