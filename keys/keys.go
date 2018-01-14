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
	"encoding/hex"
	"errors"

	"github.com/sanscentral/sanswallet/network"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil/hdkeychain"
)

// AddressType used in BIP44
type AddressType uint32

// HardenedKeyZeroIndex is the index where hardended keys start
const (
	HardenedKeyZeroIndex = 0x80000000 // 2^31

	// BIP43PurposeConstant is to-be hardened purpose (Full list of coin types available here: https://github.com/satoshilabs/slips/blob/master/slip-0044.md)
	BIP43PurposeConstant = 44

	// BTCCoinType is to-be hardened BIP44 Bitcoin coin type
	BTCCoinType = 0

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

// GetBTCAccountKey retreives bitcoin address key for BIP32 path using BIP44 standard (m / purpose' / coin_type' / account' / change / address_index)
func GetBTCAccountKey(masterKey *hdkeychain.ExtendedKey, accountIndex uint32, change AddressType, addressIndex uint32) (key *hdkeychain.ExtendedKey, err error) {
	purpose, err := masterKey.Child(HardenedKeyZeroIndex + BIP43PurposeConstant)
	if err != nil {
		return nil, err
	}

	coinType, err := purpose.Child(HardenedKeyZeroIndex + BTCCoinType)
	if err != nil {
		return nil, err
	}

	account, err := coinType.Child(HardenedKeyZeroIndex + accountIndex)
	if err != nil {
		return nil, err
	}

	changeK, err := account.Child(uint32(change))
	if err != nil {
		return nil, err
	}

	key, err = changeK.Child(addressIndex)
	if err != nil {
		return nil, err
	}

	return
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
