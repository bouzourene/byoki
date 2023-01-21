package actions

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/bouzourene/byoki/helpers"
	"github.com/hashicorp/vault/shamir"
)

func GenerateKeys(min int, total int) string {
	shamirKey, err := helpers.GeneratePassphrase()
	if err != nil {
		helpers.ErrorAndExit(err)
	}

	shares, err := shamir.Split([]byte(shamirKey), total, min)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to split secret: %v\n", err)
		os.Exit(1)
	}

	privateKey, err := crypto.GenerateKey(
		"byoki",
		"byoki@localhost",
		"rsa",
		4096,
	)

	if err != nil {
		helpers.ErrorAndExit(err)
	}

	privateKey, err = privateKey.Lock(
		[]byte(shamirKey),
	)

	if err != nil {
		helpers.ErrorAndExit(err)
	}

	privateKeyArmor, err := privateKey.Armor()
	if err != nil {
		helpers.ErrorAndExit(err)
	}

	publicKeyArmor, err := privateKey.GetArmoredPublicKey()
	if err != nil {
		helpers.ErrorAndExit(err)
	}

	var keys []string
	for _, key := range shares {
		keys = append(keys, fmt.Sprintf("%x", key))
	}

	helpers.ScreenClear()
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
		helpers.WaitForEnter()
		helpers.ScreenClear()

		fmt.Printf("%s %d\n", label, nb)
		for j := 0; j <= count; j++ {
			fmt.Printf("=")
		}
		fmt.Printf("\n\n")

		fmt.Printf("Secret key share number %d :\n", nb)
		fmt.Printf("%s\n\n", key)

		fmt.Printf("Please make sure to save this secret in a secure way.\n\n")
		fmt.Printf("> Press [Enter] to continue...")
		helpers.WaitForEnter()
		helpers.ScreenClear()
	}

	encrypted, err := helpers.EncryptMessage(
		[]byte(shamirKey),
		privateKeyArmor,
	)

	if err != nil {
		helpers.ErrorAndExit(err)
	}

	var file helpers.KeysFile
	file.CreatedOn = time.Now().Format("2006-01-02 15:04:05")
	file.Minimum = min
	file.Total = total
	file.PublicKey = publicKeyArmor
	file.PrivateKey = encrypted

	json, err := json.Marshal(file)
	if err != nil {
		helpers.ErrorAndExit(err)
	}

	return string(json)
}
