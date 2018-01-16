/*
	SansSeed is a BIP39 compatible implementation for generating mnemonic phrases and seed derivation
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

package sanswallet

import (
	"errors"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/hdkeychain"

	"github.com/sanscentral/sanswallet/keys"
	"github.com/sanscentral/sanswallet/network"
)

var (
	// Version bytes of master public/private keys indicate what type of output script should be used.
	privP2WPKHVer = [4]byte{0x04, 0xb2, 0x43, 0x0c}
	pubP2WPKHVer  = [4]byte{0x04, 0xb2, 0x47, 0x46}

	// possible prefixes for a P2WPKH key (Used for key validation)
	p2wpkhHumanPre = map[string]bool{"zpub": true, "zprv": true}
)

// GetXPrivForP2WPKHAccount returns extended private key for BIP84 P2WPKH account
func GetXPrivForP2WPKHAccount(seed []byte, accountIndex int, testnet bool) (string, error) {
	index, err := intToUint32(accountIndex)
	if err != nil {
		return "", err
	}

	net := network.BTCMainnet
	if testnet {
		net = network.BTCTestnet
	}

	m, err := keys.GetExtendedMasterPrivateKeyFromSeedBytes(seed, net)
	if err != nil {
		return "", err
	}

	k, err := keys.GetBIP84AccountKey(m, index, true)
	if err != nil {
		return "", err
	}

	return hdkeychain.VersionedStringFromExtendedKeyString(k, privP2WPKHVer)
}

// GetXPubForP2WPKHAccount returns extended public key for BIP84 P2WPKH account
func GetXPubForP2WPKHAccount(seed []byte, accountIndex int, testnet bool) (string, error) {
	index, err := intToUint32(accountIndex)
	if err != nil {
		return "", err
	}

	net := network.BTCMainnet
	if testnet {
		net = network.BTCTestnet
	}

	m, err := keys.GetExtendedMasterPrivateKeyFromSeedBytes(seed, net)
	if err != nil {
		return "", err
	}

	k, err := keys.GetBIP84AccountKey(m, index, false)
	if err != nil {
		return "", err
	}

	return hdkeychain.VersionedStringFromExtendedKeyString(k, pubP2WPKHVer)
}

// GetP2WPKHAddressForIndex returns segwit bech32 address for BTC account extended key at given index
// P2WPKH pay-to-witness-public-key-hash is the shorter segwit form of P2PKH (newest address format at time of writing, use BIP84 derived key)
func GetP2WPKHAddressForIndex(accountKey string, addressIndex int, isChange bool, testnet bool) (string, error) {
	validPre := p2wpkhHumanPre[accountKey[:4]]
	if !validPre {
		return "", errors.New("Key does not start with a P2WPKH prefix")
	}

	index, err := intToUint32(addressIndex)
	if err != nil {
		return "", err
	}

	addt := keys.ExternalAddress
	if isChange {
		addt = keys.ChangeAddress
	}

	k, err := keys.GetAccountAddressKey(accountKey, addt, index)
	if err != nil {
		return "", err
	}

	pk, err := k.ECPubKey()
	if err != nil {
		return "", err
	}

	keyHash := btcutil.Hash160(pk.SerializeCompressed())

	netParam := &chaincfg.MainNetParams
	if testnet {
		netParam = &chaincfg.TestNet3Params
	}

	segAddr, err := btcutil.NewAddressWitnessPubKeyHash(keyHash, netParam)
	if err != nil {
		return "", err
	}

	return segAddr.EncodeAddress(), nil
}
