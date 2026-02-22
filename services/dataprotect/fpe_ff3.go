package main

func ff3Encrypt(key []byte, tweak string, plaintext string, radix int) (string, error) {
	return fpeTransform(key, "ff3:"+tweak, plaintext, radix, true, 8)
}

func ff3Decrypt(key []byte, tweak string, ciphertext string, radix int) (string, error) {
	return fpeTransform(key, "ff3:"+tweak, ciphertext, radix, false, 8)
}
