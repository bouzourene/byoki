package actions

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ProtonMail/gopenpgp/v2/helper"
	"github.com/bouzourene/byoki/helpers"
)

func Encrypt(keyfile string, file string) error {

	if _, err := os.Stat(keyfile); err != nil {
		return err
	}

	if _, err := os.Stat(file); err != nil {
		return err
	}

	keyfileContent, err := os.ReadFile(keyfile)
	if err != nil {
		return err
	}

	fileContent, err := os.ReadFile(file)
	if err != nil {
		return err
	}

	var keys helpers.KeysFile
	json.Unmarshal(keyfileContent, &keys)

	encryptedFile, err := helper.EncryptBinaryMessageArmored(
		keys.PublicKey,
		fileContent,
	)

	if err != nil {
		return err
	}

	filename := filepath.Base(file)

	currentTime := time.Now()
	acrhiveName := fmt.Sprintf("encrypted-%d.byoki", currentTime.UnixNano())

	archive, err := os.Create(acrhiveName)
	if err != nil {
		return err
	}
	defer archive.Close()

	// Create a new zip writer
	wr := zip.NewWriter(archive)
	defer wr.Close()

	// Add a file to the zip file
	f1, err := wr.Create("encrypted-file")
	if err != nil {
		helpers.ErrorAndExit(err)
	}

	// Write data to the file
	_, err = f1.Write([]byte(encryptedFile))
	if err != nil {
		helpers.ErrorAndExit(err)
	}

	f2, err := wr.Create("filename")
	if err != nil {
		helpers.ErrorAndExit(err)
	}

	// Write data to the file
	_, err = f2.Write([]byte(filename))
	if err != nil {
		helpers.ErrorAndExit(err)
	}

	f3, err := wr.Create("keyfile")
	if err != nil {
		helpers.ErrorAndExit(err)
	}

	// Write data to the file
	_, err = f3.Write([]byte(keyfileContent))
	if err != nil {
		helpers.ErrorAndExit(err)
	}

	return nil
}
