package actions

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/bouzourene/byoki/helpers"
	"github.com/corvus-ch/shamir"
)

func GenerateKeys(min int, total int) string {
	shamirKey, err := helpers.GeneratePassphrase()
	if err != nil {
		log.Fatal(err) // TODO: Handle error
	}

	shares, err := shamir.Split(
		[]byte(shamirKey),
		total,
		min,
	)

	if err != nil {
		panic(err)
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

	var keys []string
	for index, key := range shares {
		var key2 string
		keyHexa := fmt.Sprintf("%x", key)

		for j, keyPart := range keyHexa {
			if j > 0 && j%4 == 0 {
				key2 += "-"
			}
			key2 = fmt.Sprintf("%s%c", key2, keyPart)
		}

		key2 = fmt.Sprintf("%x-%s", index, key2)
		keys = append(keys, key2)
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

	var file helpers.KeysFile
	file.CreatedOn = time.Now().Format("2006-01-02 15:04:05")
	file.Minimum = min
	file.Total = total
	file.PublicKey = publicKeyArmor
	//file.PrivateKey = privateKey
	file.PrivateKey = privateKeyArmor

	json, err := json.Marshal(file)
	if err != nil {
		log.Fatal(err)
	}

	return string(json)
}
