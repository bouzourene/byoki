package actions

import (
	"archive/zip"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/ProtonMail/gopenpgp/v2/helper"
	"github.com/bouzourene/byoki/helpers"
	"github.com/corvus-ch/shamir"
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
		} else {
			filedata = helpers.ReadAll(f)
		}
	}

	fmt.Printf(
		"%d / %d keys are needed to decrypt this archive\n\n",
		jsonData.Minimum,
		jsonData.Total,
	)

	var keys []string

	/*for i := 1; i <= jsonData.Minimum; i++ {
		fmt.Printf("Enter secret share number %d: ", i)

		var key string
		fmt.Scanln(&key)

		keys = append(keys, key)
	}*/
	keys = append(keys, "45-b08c-3b4a-8bbe-b057-7f61-3124-ab44-522a-7e11-afdb-38d5-67db-c386-6d93-658d-117c")
	keys = append(keys, "25-f19f-85c3-6077-3615-3d98-6e5c-ea73-4290-bc5f-29cd-50fd-760e-5857-4299-3b48-ae84")

	byteParts := make(map[byte][]byte)
	for _, key := range keys {
		index := strings.Split(key, "-")[0]
		key = key[len(index):]

		key = strings.ReplaceAll(key, "-", "")
		fmt.Println(key)
		bytePart, err := hex.DecodeString(key)
		if err != nil {
			log.Fatal(err)
		}

		byteIndex := []byte(index)
		byteParts[byteIndex[0]] = bytePart
	}
	shamirKey2, err := shamir.Combine(byteParts)
	if err != nil {
		panic(err)
	}

	/*byteParts := make(map[byte][]byte)
	for i, key := range shares {
		key = strings.ReplaceAll(key, "-", "")
		fmt.Println(key)
		bytePart, err := hex.DecodeString(key)
		if err != nil {
			log.Fatal(err)
		}

		byteParts[byte(i)] = bytePart
	}

	secret, err := shamir.Combine(byteParts)
	if err != nil {
		panic(err)
	}

	if err != nil {
		panic(err)
	}*/

	/*privateKey, err := crypto.NewKeyFromArmored(jsonData.PrivateKey)
	if err != nil {
		panic(err)
	}*/

	/*privateKey, err := crypto.NewKeyFromArmored(jsonData.PrivateKey)
	if err != nil {
		panic(err)
	}

	privateKeyUnlocked, err := privateKey.Unlock(shamirKey2)
	if err != nil {
		panic(err)
	}

	pkey, err := privateKeyUnlocked.Armor()
	if err != nil {
		panic(err)
	}
	fmt.Println(pkey)

	fileDecrypted, err := helper.DecryptAttachmentWithKey(
		pkey,
		shamirKey2,
		filedata,
		filedata,
	)*/

	fileDecrypted, err := helper.DecryptBinaryMessageArmored(
		jsonData.PrivateKey,
		shamirKey2,
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
