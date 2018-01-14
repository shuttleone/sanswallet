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

// HardenedKeyZeroIndex is the index where hardended keys start
const (
	HardenedKeyZeroIndex = 0x80000000 // 2^31
)

// GetExtendedPrivateKeyFromSeedHex returns extended private key and chain code using bytes from a decoded hex string
func GetExtendedPrivateKeyFromSeedHex(seed string, net network.Network) (privateKey *hdkeychain.ExtendedKey, err error) {
	pk, err := hex.DecodeString(seed)
	if err != nil {
		return nil, err
	}
	n, err := networkToChainCfg(net)
	return hdkeychain.NewMaster(pk, n)
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
