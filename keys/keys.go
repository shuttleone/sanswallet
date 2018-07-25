/*
	SansWallet is a BIP32, BIP44, BIP49 and BIP84 compatible hierarchical determinstic wallet
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
	"encoding/hex"
	"errors"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil/hdkeychain"

	"github.com/sanscentral/sanswallet/network"
)

// AddressType used in BIP44
type AddressType uint32

// HardenedKeyZeroIndex is the index where hardended keys start
const (
	HardenedKeyZeroIndex = 0x80000000 // 2^31

	// BIP44Purpose P2PKH purpose
	BIP44Purpose uint32 = 44

	// BIP49Purpose P2SH purpose
	BIP49Purpose uint32 = 49

	// BIP84Purpose P2WPKH purpose
	BIP84Purpose uint32 = 84

	// BTCCoinType (Full list of coin types available here: https://github.com/satoshilabs/slips/blob/master/slip-0044.md)
	BTCCoinType uint32 = 0

	ExternalAddress AddressType = 0
	ChangeAddress   AddressType = 1
)

// GetExtendedMasterPrivateKeyFromSeedHex returns extended master private key using bytes from a decoded hex string
func GetExtendedMasterPrivateKeyFromSeedHex(seed string, net network.Network) (privateKey *hdkeychain.ExtendedKey, err error) {
	pk, err := hex.DecodeString(seed)
	if err != nil {
		return nil, err
	}
	return GetExtendedMasterPrivateKeyFromSeedBytes(pk, net)
}

// GetExtendedMasterPrivateKeyFromSeedBytes returns extended master private key from bytes
func GetExtendedMasterPrivateKeyFromSeedBytes(seed []byte, net network.Network) (privateKey *hdkeychain.ExtendedKey, err error) {
	n, err := networkToChainCfg(net)
	return hdkeychain.NewMaster(seed, n)
}

// GetExtendedKeyFromString returns a new extended key from a base58-encoded extended key
func GetExtendedKeyFromString(xKey string) (key *hdkeychain.ExtendedKey, err error) {
	return hdkeychain.NewKeyFromString(xKey)
}

// GetBIP84AccountKey retreives BIP49 account key for BIP32 path using BIP44 standard (m / purpose' / coin_type' / --->account'<--- / change / address_index)
// This is primarily used for P2SH
func GetBIP84AccountKey(masterKey *hdkeychain.ExtendedKey, accountIndex uint32, includePrivateKey bool) (key string, err error) {
	return getAccountKeyWithPurpose(masterKey, BIP84Purpose, accountIndex, includePrivateKey)
}

// GetBIP49AccountKey retreives BIP49 account key for BIP32 path using BIP44 standard (m / purpose' / coin_type' / --->account'<--- / change / address_index)
// This is primarily used for P2SH
func GetBIP49AccountKey(masterKey *hdkeychain.ExtendedKey, accountIndex uint32, includePrivateKey bool) (key string, err error) {
	return getAccountKeyWithPurpose(masterKey, BIP49Purpose, accountIndex, includePrivateKey)
}

// GetBIP44AccountKey retreives BIP44 account key for BIP32 path using BIP44 standard (m / purpose' / coin_type' / --->account'<--- / change / address_index)
// This is primarily used for P2PKH
func GetBIP44AccountKey(masterKey *hdkeychain.ExtendedKey, accountIndex uint32, includePrivateKey bool) (key string, err error) {
	return getAccountKeyWithPurpose(masterKey, BIP44Purpose, accountIndex, includePrivateKey)
}

// getAccountKeyWithPurpose retrieves account key with specified BIP32 purpose
func getAccountKeyWithPurpose(masterKey *hdkeychain.ExtendedKey, purpose uint32, accountIndex uint32, includePrivateKey bool) (key string, err error) {
	purposeK, err := masterKey.Child(HardenedKeyZeroIndex + purpose)
	if err != nil {
		return "", err
	}

	coinType, err := purposeK.Child(HardenedKeyZeroIndex + BTCCoinType)
	if err != nil {
		return "", err
	}

	r, err := coinType.Child(HardenedKeyZeroIndex + accountIndex)
	if err != nil {
		return "", err
	}

	if includePrivateKey {
		return r.String(), nil
	}

	pub, err := r.Neuter()
	if err != nil {
		return "", err
	}

	return pub.String(), nil
}

// GetAccountAddressKey retreives key for BIP32 path using BIP44 standard (m / purpose' / coin_type' / account' / --->change / address_index <---)
func GetAccountAddressKey(xKey string, change AddressType, addressIndex uint32) (key *hdkeychain.ExtendedKey, err error) {
	account, err := GetExtendedKeyFromString(xKey)
	if err != nil {
		return nil, err
	}

	changeK, err := account.Child(uint32(change))
	if err != nil {
		return nil, err
	}

	return changeK.Child(addressIndex)
}

func networkToChainCfg(net network.Network) (*chaincfg.Params, error) {
	switch net {
	case network.BTCMainnet:
		return &chaincfg.MainNetParams, nil
	case network.BTCTestnet:
		return &chaincfg.TestNet3Params, nil
	}
	return nil, errors.New("Unknown network specified")
}
