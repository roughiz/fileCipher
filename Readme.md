# Python script to encrypt or decrypt a file, using 3DES cipher algo.

## Examples :

### Encrypt a file readme.md and write the output into enc.txt :

```
$ python fileCipher.py -a encrypt -f readme.md -k 'Sixteen byte key'  -o enc.txt
```

### Decrypt a file enc.txt and write the output into out.txt :

```
$ python fileCipher.py -f enc.txt -k 'Sixteen byte key' -o out.txt
```

#### Nota: key must be either 16 or 24 bytes long !

