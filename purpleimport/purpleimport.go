package main

import (
	"os"
	"strings"
	"io/ioutil"
	"regexp"
	"errors"
	"math/big"
	"code.google.com/p/go.crypto/otr"
	"encoding/base64"
	"encoding/hex"

	"fmt"
)


func otrKeysFromPurple(jid string) (sk *otr.PrivateKey, err error) {
	homeDir := os.Getenv("HOME")
	keys_bs, err := ioutil.ReadFile(homeDir + "/.purple/otr.private_key")
	if err != nil {
		return
	}
	jid = strings.Replace(jid, `.`, `\.`, -1)
	rx := `\(account\s*\(\s*name\s*"`+jid+`\/\w*"\s*\)\s*\(\s*protocol\s*prpl-jabber\s*\)\s*\(\s*private-key\s*\(dsa\s*\(p\s*#([0-9a-fA-F]+)#\s*\)\s*\(\s*q\s*#([0-9a-fA-F]+)#\s*\)\s*\(\s*g\s*#([0-9a-fA-F]+)#\s*\)\s*\(\s*y\s*#([0-9a-fA-F]+)#\s*\)\s*\(\s*x\s*#([0-9a-fA-F]+)#\s*\)\s*\)\s*\)`
	fmt.Println(rx)
	dsakey_r, err := regexp.Compile(rx)
	matches := dsakey_r.FindSubmatch(keys_bs)
	if matches == nil {
		err = errors.New("Not found")
		return
	}

	sk = new(otr.PrivateKey)
	sk.PrivateKey.PublicKey = sk.PublicKey.PublicKey
	var ok bool

	sk.PublicKey.P, ok = new(big.Int).SetString(string(matches[1]), 16)
	if !ok {return nil, errors.New("Could not read P")}
	sk.PublicKey.Q, ok = new(big.Int).SetString(string(matches[2]), 16)
	if !ok {return nil, errors.New("Could not read Q")}
	sk.PublicKey.G, ok = new(big.Int).SetString(string(matches[3]), 16)
	if !ok {return nil, errors.New("Could not read G")}
	sk.PublicKey.Y, ok = new(big.Int).SetString(string(matches[4]), 16)
	if !ok {return nil, errors.New("Could not read Y")}
	sk.PrivateKey.X, ok = new(big.Int).SetString(string(matches[5]), 16)
	if !ok {return nil, errors.New("Could not read X")}

	return
}

func main() {
	sk, err := otrKeysFromPurple(os.Args[1])
	if err != nil {
		panic(err)
	}
	bs := sk.Serialize(nil)
	fmt.Println(hex.EncodeToString(sk.Fingerprint()))
	fmt.Println(base64.StdEncoding.EncodeToString(bs))
}
