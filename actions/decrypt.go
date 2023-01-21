package actions

import (
	"archive/zip"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/ProtonMail/gopenpgp/v2/helper"
	"github.com/bouzourene/byoki/helpers"
	"github.com/hashicorp/vault/shamir"
)

func Decrypt(archive string) error {
	if _, err := os.Stat(archive); err != nil {
		return err
	}

	r, err := zip.OpenReader(archive)
	if err != nil {
		return err
	}
	defer r.Close()

	var filedata []byte
	var filename string
	var jsonData helpers.KeysFile

	// Iterate through the files in the archive
	for _, f := range r.File {
		if f.Name == "filename" {
			filename = string(helpers.ReadAll(f))
		} else if f.Name == "keyfile" {
			err = json.Unmarshal(helpers.ReadAll(f), &jsonData)
			if err != nil {
				panic(err)
			}
		} else if f.Name == "encrypted-file" {
			filedata = helpers.ReadAll(f)
		} else {
			panic("test")
		}
	}

	fmt.Printf(
		"%d / %d keys are needed to decrypt this archive\n\n",
		jsonData.Minimum,
		jsonData.Total,
	)

	var keys []string
	for i := 1; i <= jsonData.Minimum; i++ {
		fmt.Printf("Enter secret share number %d: ", i)

		var key string
		fmt.Scanln(&key)

		keys = append(keys, key)
	}

	var byteParts [][]byte
	for _, hexPart := range keys {
		b, err := hex.DecodeString(hexPart)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to decode %q: %v\n", hexPart, err)
			os.Exit(1)
		}
		byteParts = append(byteParts, b)
	}
	shamirKey, err := shamir.Combine(byteParts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to combine secret: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("%s\n", string(shamirKey))

	pkey, err := helpers.DecryptMessage(
		shamirKey,
		jsonData.PrivateKey,
	)

	if err != nil {
		panic(err)
	}

	fileDecrypted, err := helper.DecryptBinaryMessageArmored(
		pkey,
		shamirKey,
		string(filedata),
	)

	if err != nil {
		panic(err)
	}

	err = helpers.WriteBinaryFileToDisk(
		fmt.Sprintf("./%s", filename),
		fileDecrypted,
	)

	if err != nil {
		panic(err)
	}

	return nil
}
