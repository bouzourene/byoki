package helpers

type KeysFile struct {
	Minimum    int    `json:"minimum_shares"`
	Total      int    `json:"total_shares"`
	CreatedOn  string `json:"created_on"`
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

var OptionsGenerate struct {
	Output  string `short:"o" long:"output" required:"yes" description:"Filename for the new key pair"`
	Minimum int    `short:"m" long:"min" required:"yes" description:"Minimum of shares needed to retrieve the private key"`
	Total   int    `short:"t" long:"total" required:"yes" description:"Total number of secret shares, has to be higher than minimum"`
}

var OptionsEncrypt struct {
	Keyfile string `short:"k" long:"keyfile" required:"yes" description:"Path to the keyfile required for encryption"`
	File    string `short:"f" long:"file" required:"yes" description:"File to encrypt"`
}

var OptionsDecrypt struct {
	Archive string `short:"a" long:"archive" required:"yes" description:"Path to the encrypted archive"`
}
