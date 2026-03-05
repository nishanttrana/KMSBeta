.PHONY: build-linux build-macos build-windows clean

MODULE := vecta-kms/services/pkcs11-provider

build-linux:
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -buildmode=c-shared -o libvecta-pkcs11.so .

build-macos:
	CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build -buildmode=c-shared -o libvecta-pkcs11.dylib .

build-windows:
	CGO_ENABLED=1 GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc go build -buildmode=c-shared -o vecta-pkcs11.dll .

clean:
	rm -f libvecta-pkcs11.so libvecta-pkcs11.dylib vecta-pkcs11.dll *.h
