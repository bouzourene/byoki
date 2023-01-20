package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bouzourene/byoki/actions"
	"github.com/bouzourene/byoki/helpers"
	"github.com/jessevdk/go-flags"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Please provide action!")
		os.Exit(1)
	}

	allowedActions := [3]string{"genkeys", "encrypt", "decrypt"}

	args := os.Args
	action := strings.ToLower(args[1])

	if action == "genkeys" {

		_, err := flags.ParseArgs(&helpers.OptionsGenerate, args)
		if err != nil {
			panic(err)
		}

		output := actions.GenerateKeys(
			helpers.OptionsGenerate.Minimum,
			helpers.OptionsGenerate.Total,
		)

		err = helpers.WriteFileToDisk(helpers.OptionsGenerate.Output, output)
		if err != nil {
			panic(err)
		}

		outputPath := helpers.OptionsGenerate.Output
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

		_, err := flags.ParseArgs(&helpers.OptionsEncrypt, args)
		if err != nil {
			panic(err)
		}

		err = actions.Encrypt(
			helpers.OptionsEncrypt.Keyfile,
			helpers.OptionsEncrypt.File,
		)

		if err != nil {
			panic(err)
		}

	} else if action == "decrypt" {

		_, err := flags.ParseArgs(&helpers.OptionsDecrypt, args)
		if err != nil {
			panic(err)
		}

		err = actions.Decrypt(helpers.OptionsDecrypt.Archive)
		if err != nil {
			panic(err)
		}

	} else {
		fmt.Println("The action provided in not valid!")
		fmt.Printf("Valid actions: %v\n", allowedActions)

		os.Exit(1)
	}
}
