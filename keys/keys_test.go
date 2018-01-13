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
	"testing"
)

const (
	testPrivateKeyHex = "3aba4162c7251c891207b747840551a71939b0de081f85c4e44cf7c13e41daa6"
	testSeedHexA      = "f44e3fc5fc4fbc5e36570bfebade1dcba940260b8c61be1ee2dda8f49cdaabbb09a75a55f4cbbe647b6e85ba9f482e9b18fe28a788af2bec5b76c3a0dc31d53c"
	testSeedHexB      = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
)

func TestPrivateKeyFromBytes(t *testing.T) {
	pk, err := hex.DecodeString(testPrivateKeyHex)
	if err != nil {
		t.Error(err)
	}
	if len(pk) != 32 {
		t.Errorf("Private key is not expected length")
	}

	kp, err := getKeyPairFromBytes(pk)
	if err != nil {
		t.Error(err)
	}

	if kp.D.String() != "26563230048437957592232553826663696440606756685920117476832299673293013768870" {
		t.Errorf("Unexpected private key in EDCSA pair")
	}

	if kp.PublicKey.X.String() != "41637322786646325214887832269588396900663353932545912953362782457239403430124" {
		t.Errorf("Unexpected X coordinate in keypair")
	}

	if kp.PublicKey.Y.String() != "16388935128781238405526710466724741593761085120864331449066658622400339362166" {
		t.Errorf("Unexpected Y coordinate in keypair")
	}
}

func TestKeyRetrievalA(t *testing.T) {
	pk, cc, err := GetKeyAndChainCodeFromSeedHex(testSeedHexA)
	if err != nil {
		t.Error(err)
		t.Fail()
	}

	if len(pk.D.Bytes()) != 32 {
		t.Errorf("Private key is not expected length")
	}

	if len(cc) != 32 {
		t.Errorf("Chain code is not expected length")
	}
}
