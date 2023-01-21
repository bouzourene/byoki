package helpers

import (
	"archive/zip"
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"runtime"

	"github.com/sethvargo/go-password/password"
)

func GeneratePassphrase() (string, error) {
	passphrase, err := password.Generate(32, 10, 10, false, false)
	if err != nil {
		return "", err
	}

	return passphrase, nil
}

func WriteFileToDisk(path string, content string) error {
	return os.WriteFile(path, []byte(content), 0777)
}

func WriteBinaryFileToDisk(path string, content []byte) error {
	return os.WriteFile(path, content, 0777)
}

func ScreenClear() {
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

func WaitForEnter() {
	bufio.NewReader(os.Stdin).ReadBytes('\n')
}

func ReadAll(file *zip.File) []byte {
	fc, err := file.Open()
	Check(err)
	defer CloseFile(fc)

	content, err := ioutil.ReadAll(fc)
	Check(err)

	return content
}

func Check(e error) {
	if e != nil {
		panic(e)
	}
}

type MyCloser interface {
	Close() error
}

// closeFile is a helper function which streamlines closing
// with error checking on different file types.
func CloseFile(f MyCloser) {
	err := f.Close()
	Check(err)
}

func EncryptMessage(key []byte, message string) (string, error) {
	byteMsg := []byte(message)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("could not create new cipher: %v", err)
	}

	cipherText := make([]byte, aes.BlockSize+len(byteMsg))
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return "", fmt.Errorf("could not encrypt: %v", err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], byteMsg)

	return base64.StdEncoding.EncodeToString(cipherText), nil
}

func DecryptMessage(key []byte, message string) (string, error) {
	cipherText, err := base64.StdEncoding.DecodeString(message)
	if err != nil {
		return "", fmt.Errorf("could not base64 decode: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("could not create new cipher: %v", err)
	}

	if len(cipherText) < aes.BlockSize {
		return "", fmt.Errorf("invalid ciphertext block size")
	}

	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)

	return string(cipherText), nil
}
