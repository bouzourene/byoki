package main

import (
	"archive/zip"
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/ProtonMail/gopenpgp/v2/helper"
	"github.com/corvus-ch/shamir"
	"github.com/jessevdk/go-flags"
	"github.com/sethvargo/go-password/password"
)

type KeysFile struct {
	Minimum    int    `json:"minimum_shares"`
	Total      int    `json:"total_shares"`
	CreatedOn  string `json:"created_on"`
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

var optionsGenerate struct {
	Output  string `short:"o" long:"output" required:"yes" description:"Filename for the new key pair"`
	Minimum int    `short:"m" long:"min" required:"yes" description:"Minimum of shares needed to retrieve the private key"`
	Total   int    `short:"t" long:"total" required:"yes" description:"Total number of secret shares, has to be higher than minimum"`
}

var optionsEncrypt struct {
	Keyfile string `short:"k" long:"keyfile" required:"yes" description:"Path to the keyfile required for encryption"`
	File    string `short:"f" long:"file" required:"yes" description:"File to encrypt"`
}

var optionsDecrypt struct {
	Keys    string `short:"k" long:"keys" required:"yes" description:"Path to the keys required for decryption"`
	Archive string `short:"a" long:"archive" required:"yes" description:"Path to the encrypted archive"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Please provide action!")
		os.Exit(1)
	}

	actions := [3]string{"genkeys", "encrypt", "decrypt"}

	args := os.Args
	action := strings.ToLower(args[1])

	if action == "genkeys" {
		_, err := flags.ParseArgs(&optionsGenerate, args)
		if err != nil {
			panic(err)
		}

		output := generateKeys(
			optionsGenerate.Minimum,
			optionsGenerate.Total,
		)

		err = writeFileToDisk(optionsGenerate.Output, output)
		if err != nil {
			panic(err)
		}

		outputPath := optionsGenerate.Output
		absolute, err := filepath.Abs(outputPath)
		if err == nil {
			outputPath = absolute
		}

		fmt.Printf("All keys have been generated\n")
		fmt.Printf("============================\n\n")
		fmt.Printf(
			"The keys have been exported successfuly to:\n%s\n\n",
			absolute,
		)

	} else if action == "encrypt" {
		_, err := flags.ParseArgs(&optionsEncrypt, args)
		if err != nil {
			panic(err)
		}

		err = encrypt(
			optionsEncrypt.Keyfile,
			optionsEncrypt.File,
		)

		if err != nil {
			panic(err)
		}

	} else if action == "decrypt" {
		decrypt()
	} else {
		fmt.Println("The action provided in not valid!")
		fmt.Printf("Valid actions: %v\n", actions)

		os.Exit(1)
	}
}

func generateKeys(min int, total int) string {
	shamirKey, err := genPassphrase()
	if err != nil {
		log.Fatal(err) // TODO: Handle error
	}

	privateKey, err := crypto.GenerateKey(
		"byoki",
		"byoki@localhost",
		"rsa",
		4096,
	)

	if err != nil {
		log.Fatal(err) // TODO: Handle error
	}

	privateKey, err = privateKey.Lock(
		[]byte(shamirKey),
	)

	if err != nil {
		log.Fatal(err) // TODO: Handle error
	}

	privateKeyArmor, err := privateKey.Armor()
	if err != nil {
		log.Fatal(err) // TODO: Handle error
	}

	publicKeyArmor, err := privateKey.GetArmoredPublicKey()
	if err != nil {
		log.Fatal(err) // TODO: Handle error
	}

	privateKeyEncrypted, err := helper.EncryptMessageWithPassword(
		[]byte(shamirKey),
		privateKeyArmor,
	)

	if err != nil {
		log.Fatal(err) // TODO: Handle error
	}

	shares, err := shamir.Split(
		[]byte(shamirKey),
		total,
		min,
	)

	if err != nil {
		log.Fatal(err) // TODO: Handle error
	}

	var keys []string
	for _, share := range shares {
		key := fmt.Sprintf("%x", share)
		keys = append(keys, key)
	}

	for i, key := range keys {
		var key2 string
		for j, keyPart := range key {
			if j > 0 && j%4 == 0 {
				key2 += "-"
			}
			key2 = fmt.Sprintf("%s%c", key2, keyPart)
		}
		keys[i] = key2
	}

	screenClear()
	for i, key := range keys {
		nb := i + 1
		label := "Secret share number"
		count := len(label) + len(fmt.Sprint(nb))

		fmt.Printf("%s %d\n", label, nb)
		for j := 0; j <= count; j++ {
			fmt.Printf("=")
		}
		fmt.Printf("\n\n")

		fmt.Printf("Please make sure secret holder number %d is alone behind this terminal.\n\n", nb)
		fmt.Printf("> Press [Enter] to continue...")
		waitForEnter()
		screenClear()

		fmt.Printf("%s %d\n", label, nb)
		for j := 0; j <= count; j++ {
			fmt.Printf("=")
		}
		fmt.Printf("\n\n")

		fmt.Printf("Secret key share number %d :\n", nb)
		fmt.Printf("%s\n\n", key)

		fmt.Printf("Please make sure to save this secret in a secure way.\n\n")
		fmt.Printf("> Press [Enter] to continue...")
		waitForEnter()
		screenClear()
	}

	var file KeysFile
	file.CreatedOn = time.Now().Format("2006-01-02 15:04:05")
	file.Minimum = min
	file.Total = total
	file.PublicKey = publicKeyArmor
	file.PrivateKey = privateKeyEncrypted

	json, err := json.Marshal(file)
	if err != nil {
		log.Fatal(err)
	}

	return string(json)
}

func encrypt(keyfile string, file string) error {

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

	fileContent, err := os.ReadFile(keyfile)
	if err != nil {
		return err
	}

	var keys KeysFile
	json.Unmarshal(keyfileContent, &keys)

	encryptedFile, err := helper.EncryptAttachmentWithKey(
		keys.PublicKey,
		"encrypted-data",
		fileContent,
	)

	if err != nil {
		return err
	}

	filename := filepath.Base(file)

	currentTime := time.Now()
	acrhiveName := fmt.Sprintf("./test/encrypted-%d.zip", currentTime.UnixNano())

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
		log.Fatal(err)
	}

	// Write data to the file
	_, err = f1.Write(encryptedFile.GetBinary())
	if err != nil {
		log.Fatal(err)
	}

	f2, err := wr.Create("filename")
	if err != nil {
		log.Fatal(err)
	}

	// Write data to the file
	_, err = f2.Write([]byte(filename))
	if err != nil {
		log.Fatal(err)
	}

	f3, err := wr.Create("keyfile")
	if err != nil {
		log.Fatal(err)
	}

	// Write data to the file
	_, err = f3.Write([]byte(keyfileContent))
	if err != nil {
		log.Fatal(err)
	}

	return nil
}

func decrypt() {

}

func genPassphrase() (string, error) {
	passphrase, err := password.Generate(32, 10, 10, false, false)
	if err != nil {
		return "", err
	}

	return passphrase, nil
}

func writeFileToDisk(path string, content string) error {
	return os.WriteFile(path, []byte(content), 0777)
}

func screenClear() {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("cmd", "/c", "cls")
		cmd.Stdout = os.Stdout
		cmd.Run()
	} else {
		cmd := exec.Command("clear")
		cmd.Stdout = os.Stdout
		cmd.Run()
	}
}

func waitForEnter() {
	bufio.NewReader(os.Stdin).ReadBytes('\n')
}
