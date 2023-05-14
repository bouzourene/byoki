# Byoki
Byoki is a CLI tool that combines PGP asymetric encryption with the concept of Shamir Split Secrets for decryption.

## Example usecase
I need to make automated and encrypted backups for a database (it could be anything, really), but I need to make sure that only one person is not enough to decrypt it.
That's when Shamir Split Secrets becomes useful, it allows us to choose a total number of secret keys and to set a threshold to allow decryption. Each trusted user is given a personnal key, but they will have to work together in order to unlock the archive.

## Useful links
- [Shamir Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing)
- [GPG](https://en.wikipedia.org/wiki/GNU_Privacy_Guard)

## How to use
1. Create a JSON keys file (it will contain a public key, an encrypted private key, as well as some useful metadata)
```
./byoki genkeys -m [shamir threshold, ex: 2] -t [shamir total shares, ex: 4] -o [path to output file, ex: keys.json]
```
2. Encrypt a file or an archive with our newly created key
```
./byoki encrypt -k [path to our keys file, ex: keys.json] -k [path to the file to encrypt, ex: archive.zip]
```
3. Decrypt our archive with the threshold amount of Shamir secrets
```
./byoki decrypt -a [path to the encrypted archive, ex: archive-xyz.byoki]
```
