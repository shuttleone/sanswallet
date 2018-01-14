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
	"testing"

	"github.com/sanscentral/sanswallet/network"
)

const (
	testSeedHexA = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
	//testSeedHexB = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
)

// Test data taken from https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#Test_vector_1
func TestXMasterKeyA(t *testing.T) {
	// Generate a new master node from seed (Chain m)
	key, err := GetExtendedPrivateKeyFromSeedHex(testSeedHexA, network.BTCMainnet)
	if err != nil {
		t.Error(err)
	}

	if key.String() != "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U" {
		t.Errorf("Private key is not expected value")
	}

	pubK, err := key.Neuter()
	if err != nil {
		t.Error(err)
	}

	if pubK.String() != "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB" {
		t.Errorf("Public key is not expected value")
	}

	// (Chain m/0)
	mzero, err := key.Child(0)
	if err != nil {
		t.Error(err)
	}

	if mzero.String() != "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt" {
		t.Errorf("m/0 Private key is not expected value")
	}

	mzeroPub, err := mzero.Neuter()
	if err != nil {
		t.Error(err)
	}

	if mzeroPub.String() != "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH" {
		t.Errorf("Public key is not expected value")
	}

	// (Chain m/0/2147483647(H))
	mz2147483647, err := mzero.Child(HardenedKeyZeroIndex + 2147483647)
	if err != nil {
		t.Error(err)
	}

	if mz2147483647.String() != "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9" {
		t.Errorf("m/0/2147483647 Private key is not expected value")
	}

}
