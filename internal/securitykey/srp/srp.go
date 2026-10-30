// Copyright 2013-2017 Sudhi Herle; adapted by blacktop (MIT).
// GrandSlam-only subset; see ../LICENSE.ipsw and ../NOTICE.md.
package srp

import (
	"crypto/sha256"
	"math/big"
)

// GrandSlam uses the fixed 2048-bit SRP group with generator 2.
var (
	modulus, _ = new(big.Int).SetString("0xAC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73", 0)
	generator  = big.NewInt(2)
)

type PasswordProtocol string

const (
	// ProtocolS2K feeds the raw SHA-256 digest into PBKDF2.
	ProtocolS2K PasswordProtocol = "s2k"
	// ProtocolS2KFO feeds its lowercase hex encoding into PBKDF2.
	ProtocolS2KFO PasswordProtocol = "s2k_fo"
)

func hashbyte(values ...[]byte) []byte {
	h := sha256.New()
	for _, value := range values {
		h.Write(value)
	}

	return h.Sum(nil)
}

func hashint(values ...[]byte) *big.Int {
	return new(big.Int).SetBytes(hashbyte(values...))
}

func xorBytes(a, b []byte) []byte {
	if len(a) != len(b) {
		return nil
	}

	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] ^ b[i]
	}

	return result
}
