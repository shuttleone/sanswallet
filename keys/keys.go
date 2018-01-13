/*
	SansWallet is a golang library implementation of a BIP32 & BIP44 hierarchical determinstic wallet
	Copyright (C) 2018  Sans Central

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU Affero General Public License as
	published by the Free Software Foundation, either version 3 of the
	License, or (at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU Affero General Public License for more details.

	You should have received a copy of the GNU Affero General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package keys

import (
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"math/big"

	"github.com/btcsuite/btcd/btcec"
)

// GetKeyAndChainCodeFromSeedHex returns the private key and chain code using bytes from a decoded hex string
func GetKeyAndChainCodeFromSeedHex(seed string) (privateKey *ecdsa.PrivateKey, chainCode []byte, err error) {
	b, err := hex.DecodeString(seed)
	if err != nil {
		return nil, []byte{}, err
	}
	return GetKeyAndChainCodeFromSeedBytes(b)
}

// GetKeyAndChainCodeFromSeedBytes returns the private key and chain code from bytes
func GetKeyAndChainCodeFromSeedBytes(seed []byte) (privateKey *ecdsa.PrivateKey, chainCode []byte, err error) {
	if len(seed) != 64 {
		return nil, []byte{}, errors.New("Invalid seed length")
	}

	privateKeyBytes := make([]byte, 32)
	copy(privateKeyBytes, seed[:32])

	privateKey, err = getKeyPairFromBytes(privateKeyBytes)
	if err != nil {
		return nil, []byte{}, errors.New("Invalid seed length")
	}

	chainCode = make([]byte, 32)
	copy(chainCode, seed[32:])
	return
}

// getKeyPairFromBytes returns a ECDSA keypair using elliptic curve secp256k1 (koblitz)
func getKeyPairFromBytes(prikb []byte) (*ecdsa.PrivateKey, error) {
	if len(prikb) <= 0 {
		return nil, errors.New("bad bytes for key")
	}

	curve := btcec.S256()
	p := new(ecdsa.PrivateKey)
	p.PublicKey.Curve = curve
	n := big.NewInt(0)
	n.SetBytes(prikb)

	if n.String() == "0" {
		return nil, errors.New("failed to set bytes in keypair")
	}

	p.D = n
	p.PublicKey.X, p.PublicKey.Y = curve.ScalarBaseMult(prikb)
	return p, nil
}
