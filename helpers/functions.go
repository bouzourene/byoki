package helpers

import (
	"archive/zip"
	"bufio"
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
