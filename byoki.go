package main

import (
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

const (
	TempDir = "./tmp"
)

var optionsGenerate struct {
	Output  string `short:"o" long:"output" required:"yes" description:"Filename for the new key pair"`
	Minimum int    `short:"m" long:"min" required:"yes" description:"Minimum of shares needed to retrieve the private key"`
	Total   int    `short:"t" long:"total" required:"yes" description:"Total number of secret shares, has to be higher than minimum"`
}

var optionsEncrypt struct {
	Keys  string   `short:"k" long:"keys" required:"yes" description:"Path to the keys required for encryption"`
	Files []string `short:"f" long:"files" required:"yes" description:"File(s) to add to encrypted archive"`
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

		fmt.Printf("All keys have been generated\n==================\n\n")
		fmt.Printf(
			"The keys have been exported successfuly to:\n%s\n\n",
			absolute,
		)

	} else if action == "encrypt" {
		encrypt()
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

		fmt.Printf("Secret key number %d\n======================\n\n", nb)
		fmt.Printf("Please make sure secret holder number %d is alone behind this terminal.\n\n", nb)
		fmt.Printf("> Press [Enter] to continue...")
		waitForEnter()
		screenClear()

		fmt.Printf("Secret key number %d\n======================\n\n", nb)
		fmt.Printf("Key part number %d :\n", nb)
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

func encrypt() {

}

func decrypt() {

}

/*
func oldMain() {

	// Create a buffer to write our archive to.
	buf := new(bytes.Buffer)

	// Create a new zip archive.
	w := zip.NewWriter(buf)

	shamirKey, err := genPassphrase()
	if err != nil {
		log.Fatal(err)
	}

	privateKey, err := crypto.GenerateKey("byoki", "byoki@localhost", "rsa", 4096)
	if err != nil {
		log.Fatal(err)
	}

	privateKey, err = privateKey.Lock([]byte(shamirKey))
	if err != nil {
		log.Fatal(err)
	}

	privateKeyArmor, err := privateKey.Armor()
	if err != nil {
		return
	}

	publicKeyArmor, err := privateKey.GetArmoredPublicKey()
	if err != nil {
		return
	}

	privateKeyEncrypted, err := helper.EncryptMessageWithPassword([]byte(shamirKey), privateKeyArmor)
	if err != nil {
		return
	}

	os.WriteFile(getTempLocation("private.key"), []byte(privateKeyEncrypted), 0777)
	os.WriteFile(getTempLocation("public.key"), []byte(publicKeyArmor), 0777)

	f, err := w.Create("private.key")
	if err != nil {
		log.Fatal(err)
	}
	_, err = f.Write([]byte(privateKeyEncrypted))
	if err != nil {
		log.Fatal(err)
	}

	f2, err := w.Create("public.key")
	if err != nil {
		log.Fatal(err)
	}
	_, err = f2.Write([]byte(publicKeyArmor))
	if err != nil {
		log.Fatal(err)
	}

	shares, err := shamir.Split([]byte(shamirKey), 4, 2)
	if err != nil {
		log.Fatal(err)
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

	for i, key := range keys {
		fmt.Printf("[%d] %s\n", i, key)
	}

	testFile, err := os.ReadFile("./test.txt")
	if err != nil {
		return
	}

	testFileArmor, err := helper.EncryptMessageArmored(publicKeyArmor, string(testFile))
	if err != nil {
		return
	}

	os.WriteFile(getTempLocation("test.txt.encrypted"), []byte(testFileArmor), 0777)

	f3, err := w.Create("blob")
	if err != nil {
		log.Fatal(err)
	}
	_, err = f3.Write([]byte(testFileArmor))
	if err != nil {
		log.Fatal(err)
	}

	f4, err := w.Create("metadata")
	if err != nil {
		log.Fatal(err)
	}
	_, err = f4.Write([]byte("filename: test.txts"))
	if err != nil {
		log.Fatal(err)
	}

	testFile2, err := os.ReadFile(getTempLocation("test.txt.encrypted"))
	if err != nil {
		return
	}

	var byteParts [][]byte
	for _, key := range keys {
		key = strings.ReplaceAll(key, "-", "")
		fmt.Println(key)

		bytePart, err := hex.DecodeString(key)
		if err != nil {
			log.Fatal(err)
		}

		byteParts = append(byteParts, bytePart)
	}

	shamirKey2, err := shamir.Combine(byteParts)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	shamirKey2Str := string(shamirKey2)
	fmt.Println(shamirKey2Str)

	privateKeyDecrypted, err := helper.DecryptMessageWithPassword([]byte(shamirKey2Str), privateKeyEncrypted)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	decrypted, err := helper.DecryptMessageArmored(privateKeyDecrypted, []byte(shamirKey2Str), string(testFile2))
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	os.WriteFile(getTempLocation("test.txt.decrypted"), []byte(decrypted), 0777)

	// Make sure to check the error on Close.
	err = w.Close()
	if err != nil {
		log.Fatal(err)
	}

	os.WriteFile(getTempLocation("test.zip"), buf.Bytes(), 0777)
}
*/

func genPassphrase() (string, error) {
	passphare, err := password.Generate(32, 10, 10, false, false)
	if err != nil {
		return "", err
	}

	return passphare, nil
}

func getTempLocation(filename string) string {
	return fmt.Sprintf("%s/%s", TempDir, filename)
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
