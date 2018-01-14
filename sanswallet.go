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
	"github.com/btcsuite/btcutil/hdkeychain"

	"github.com/sanscentral/sanswallet/keys"
	"github.com/sanscentral/sanswallet/network"
)

// Keychain represents a managed key store
type Keychain struct {
	master   *hdkeychain.ExtendedKey
	accounts []Account
}

// Account is a BIP44 'account' as defined through a BIP32 path (m / purpose' / coin_type' / --->account'<--- / change / address_index)
type Account struct {
	publicExtended *hdkeychain.ExtendedKey
	index          uint32
	address        []Address
}

// Address is a used address with given BIP32 address index
type Address struct {
	index    uint32
	isChange bool
	used     bool
}

// NewKeychainFromSeed creates a new keychain (acts as seed restore using 'Account discovery' as per BIP44)
func NewKeychainFromSeed(seed []byte) (Keychain, error) {
	n := Keychain{}
	var err error
	n.master, err = keys.GetExtendedMasterPrivateKeyFromSeedBytes(seed, network.BTCMainnet)
	if err != nil {
		return Keychain{}, err
	}

	// Perform recovery (Check with network as to accounts used)

	n.storeMasterKey()
	n.master.Zero()
	return n, nil
}

// storeMasterKey securely store the user's master key
func (k *Keychain) storeMasterKey() {

}

// readMasterKey read the user's master key from secure location (adding additional account / new cointype)
func (k *Keychain) readMasterKey() {

}

// Serialize Keychain for storage
func (k *Keychain) Serialize() {

}

// Deserialize keychain from storage
func (k *Keychain) Deserialize() {

}
