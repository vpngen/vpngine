package naclkey

import (
	"encoding/json"
	"fmt"
	"os"
)

const NaclBoxKeyLength = 32

type naclBoxKeypairValue struct {
	Private []byte `json:"private"`
	Public  []byte `json:"public"`
}

type naclBoxPublicKeyValue struct {
	Public []byte `json:"public"`
}

type naclBoxKeypair struct {
	Keypair naclBoxKeypairValue `json:"sealed-box-privkey"`
}

type naclBoxPublicKey struct {
	Pubkey naclBoxPublicKeyValue `json:"sealed-box-pubkey"`
}

type NaclBoxKeypair struct {
	Private [NaclBoxKeyLength]byte
	Public  [NaclBoxKeyLength]byte
}

func ReadKeypairFile(name string) (NaclBoxKeypair, error) {
	blob, err := os.ReadFile(name)
	if err != nil {
		return NaclBoxKeypair{}, fmt.Errorf("failed to read %s: %v", name, err)
	}
	return UnmarshalKeypair(blob)
}

func UnmarshalKeypair(blob []byte) (NaclBoxKeypair, error) {
	var ret NaclBoxKeypair
	var key naclBoxKeypair
	err := json.Unmarshal(blob, &key)
	if err != nil {
		return ret, fmt.Errorf("failed to read JSON key: %v", err)
	}
	if len(key.Keypair.Private) != NaclBoxKeyLength || len(key.Keypair.Public) != NaclBoxKeyLength {
		return ret, fmt.Errorf("bad key length, not %d bytes but %d for Private and %d for Public", NaclBoxKeyLength, len(key.Keypair.Private), len(key.Keypair.Public))
	}
	copy(ret.Public[:], key.Keypair.Public)
	copy(ret.Private[:], key.Keypair.Private)
	return ret, nil
}

func MarshalKeypair(key NaclBoxKeypair) ([]byte, error) {
	var js naclBoxKeypair
	js.Keypair.Public = key.Public[:]
	js.Keypair.Private = key.Private[:]
	blob, err := json.Marshal(&js)
	if err != nil {
		return nil, err
	}
	return blob, nil
}

func ReadPublicKeyFile(name string) ([NaclBoxKeyLength]byte, error) {
	blob, err := os.ReadFile(name)
	if err != nil {
		return [NaclBoxKeyLength]byte{}, fmt.Errorf("failed to read %s: %v", name, err)
	}
	return UnmarshalPublicKey(blob)
}

func UnmarshalPublicKey(blob []byte) ([NaclBoxKeyLength]byte, error) {
	var ret [NaclBoxKeyLength]byte
	var js naclBoxPublicKey
	err := json.Unmarshal(blob, &js)
	if err != nil {
		return ret, fmt.Errorf("failed to read JSON key: %v", err)
	}
	if len(js.Pubkey.Public) != NaclBoxKeyLength {
		return ret, fmt.Errorf("bad key length (not %d bytes but %d)", NaclBoxKeyLength, len(js.Pubkey.Public))
	}
	copy(ret[:], js.Pubkey.Public)
	return ret, nil
}

func MarshalPublicKey(key [NaclBoxKeyLength]byte) ([]byte, error) {
	var js naclBoxPublicKey
	js.Pubkey.Public = key[:]
	blob, err := json.Marshal(&js)
	if err != nil {
		return nil, err
	}
	return blob, nil
}
