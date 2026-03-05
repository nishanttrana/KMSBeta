package main

/*
#include <stdlib.h>

// PKCS#11 return codes
#define CKR_OK                          0x00000000
#define CKR_GENERAL_ERROR               0x00000005
#define CKR_ARGUMENTS_BAD               0x00000007
#define CKR_SLOT_ID_INVALID             0x00000003
#define CKR_SESSION_HANDLE_INVALID      0x000000B3
#define CKR_SESSION_CLOSED              0x000000B0
#define CKR_USER_NOT_LOGGED_IN          0x00000101
#define CKR_OPERATION_NOT_INITIALIZED   0x00000091
#define CKR_FUNCTION_NOT_SUPPORTED      0x00000054
#define CKR_CRYPTOKI_NOT_INITIALIZED    0x00000190
#define CKR_CRYPTOKI_ALREADY_INITIALIZED 0x00000191

typedef unsigned long CK_RV;
typedef unsigned long CK_SLOT_ID;
typedef unsigned long CK_SESSION_HANDLE;
typedef unsigned long CK_ULONG;
typedef unsigned long CK_OBJECT_HANDLE;
typedef unsigned long CK_FLAGS;
typedef unsigned char CK_BYTE;
typedef unsigned char CK_BBOOL;

#define CK_TRUE  1
#define CK_FALSE 0
*/
import "C"

import (
	"context"
	"log"
	"os"
	"sync"
	"time"
	"unsafe"

	"vecta-kms/pkg/keycache"
)

var (
	globalMu      sync.Mutex
	initialized   bool
	providerCfg   ProviderConfig
	kmsClient     *KMSClient
	sessionMgr    *SessionManager
	keyCache      *keycache.Cache
	providerLog   *log.Logger
)

//export C_Initialize
func C_Initialize(pInitArgs unsafe.Pointer) C.CK_RV {
	globalMu.Lock()
	defer globalMu.Unlock()

	if initialized {
		return C.CKR_CRYPTOKI_ALREADY_INITIALIZED
	}

	providerLog = log.New(os.Stderr, "[vecta-pkcs11] ", log.LstdFlags|log.LUTC)
	providerCfg = LoadProviderConfig()

	var err error
	kmsClient, err = NewKMSClient(providerCfg)
	if err != nil {
		providerLog.Printf("C_Initialize: KMS client init failed: %v", err)
		return C.CKR_GENERAL_ERROR
	}

	sessionMgr = NewSessionManager()

	cacheTTL := time.Duration(providerCfg.KeyCacheTTL) * time.Second
	cacheEnabled := providerCfg.KeyCacheTTL > 0
	keyCache = keycache.New(cacheEnabled, cacheTTL)
	if cacheEnabled {
		keyCache.StartEvictionLoop(30 * time.Second)
	}

	initialized = true
	providerLog.Printf("C_Initialize: provider ready, base_url=%s", providerCfg.BaseURL)
	return C.CKR_OK
}

//export C_Finalize
func C_Finalize(pReserved unsafe.Pointer) C.CK_RV {
	globalMu.Lock()
	defer globalMu.Unlock()

	if !initialized {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}

	if keyCache != nil {
		keyCache.Close()
	}
	if sessionMgr != nil {
		sessionMgr.CloseAll()
	}
	initialized = false
	providerLog.Printf("C_Finalize: provider shutdown")
	return C.CKR_OK
}

//export C_GetSlotList
func C_GetSlotList(tokenPresent C.CK_BBOOL, pSlotList *C.CK_SLOT_ID, pulCount *C.CK_ULONG) C.CK_RV {
	if !initialized {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	// Single slot representing the KMS tenant
	if pSlotList == nil {
		*pulCount = 1
		return C.CKR_OK
	}
	*pSlotList = 0
	*pulCount = 1
	return C.CKR_OK
}

//export C_OpenSession
func C_OpenSession(slotID C.CK_SLOT_ID, flags C.CK_FLAGS, pApplication unsafe.Pointer, notify unsafe.Pointer, phSession *C.CK_SESSION_HANDLE) C.CK_RV {
	if !initialized {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	if slotID != 0 {
		return C.CKR_SLOT_ID_INVALID
	}
	handle := sessionMgr.Open(uint64(slotID))
	*phSession = C.CK_SESSION_HANDLE(handle)
	return C.CKR_OK
}

//export C_CloseSession
func C_CloseSession(hSession C.CK_SESSION_HANDLE) C.CK_RV {
	if !initialized {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	sessionMgr.Close(uint64(hSession))
	return C.CKR_OK
}

//export C_Login
func C_Login(hSession C.CK_SESSION_HANDLE, userType C.CK_ULONG, pPin *C.CK_BYTE, ulPinLen C.CK_ULONG) C.CK_RV {
	if !initialized {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	sess, ok := sessionMgr.Get(uint64(hSession))
	if !ok {
		return C.CKR_SESSION_HANDLE_INVALID
	}
	// Auth is handled via env config; PIN is accepted but not required
	sess.LoggedIn = true
	return C.CKR_OK
}

//export C_FindObjectsInit
func C_FindObjectsInit(hSession C.CK_SESSION_HANDLE, pTemplate unsafe.Pointer, ulCount C.CK_ULONG) C.CK_RV {
	if !initialized {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	sess, ok := sessionMgr.Get(uint64(hSession))
	if !ok {
		return C.CKR_SESSION_HANDLE_INVALID
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	keys, err := kmsClient.ListKeys(ctx)
	if err != nil {
		providerLog.Printf("C_FindObjectsInit: list keys failed: %v", err)
		return C.CKR_GENERAL_ERROR
	}

	sess.FindActive = true
	sess.FindKeys = keys
	sess.FindIndex = 0
	return C.CKR_OK
}

//export C_FindObjects
func C_FindObjects(hSession C.CK_SESSION_HANDLE, phObject *C.CK_OBJECT_HANDLE, ulMaxObjectCount C.CK_ULONG, pulObjectCount *C.CK_ULONG) C.CK_RV {
	if !initialized {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	sess, ok := sessionMgr.Get(uint64(hSession))
	if !ok {
		return C.CKR_SESSION_HANDLE_INVALID
	}
	if !sess.FindActive {
		return C.CKR_OPERATION_NOT_INITIALIZED
	}

	var count C.CK_ULONG
	max := int(ulMaxObjectCount)
	handles := (*[1 << 20]C.CK_OBJECT_HANDLE)(unsafe.Pointer(phObject))

	for count < C.CK_ULONG(max) && sess.FindIndex < len(sess.FindKeys) {
		handles[count] = C.CK_OBJECT_HANDLE(sess.FindKeys[sess.FindIndex].ObjectHandle)
		sess.FindIndex++
		count++
	}
	*pulObjectCount = count
	return C.CKR_OK
}

//export C_FindObjectsFinal
func C_FindObjectsFinal(hSession C.CK_SESSION_HANDLE) C.CK_RV {
	if !initialized {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	sess, ok := sessionMgr.Get(uint64(hSession))
	if !ok {
		return C.CKR_SESSION_HANDLE_INVALID
	}
	sess.FindActive = false
	sess.FindKeys = nil
	sess.FindIndex = 0
	return C.CKR_OK
}

//export C_EncryptInit
func C_EncryptInit(hSession C.CK_SESSION_HANDLE, pMechanism unsafe.Pointer, hKey C.CK_OBJECT_HANDLE) C.CK_RV {
	if !initialized {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	sess, ok := sessionMgr.Get(uint64(hSession))
	if !ok {
		return C.CKR_SESSION_HANDLE_INVALID
	}
	// Map handle to key ID (simplified: use last FindObjects results or direct lookup)
	sess.EncryptKeyID = resolveKeyID(sess, uint64(hKey))
	if sess.EncryptKeyID == "" {
		return C.CKR_ARGUMENTS_BAD
	}
	return C.CKR_OK
}

//export C_Encrypt
func C_Encrypt(hSession C.CK_SESSION_HANDLE, pData *C.CK_BYTE, ulDataLen C.CK_ULONG, pEncryptedData *C.CK_BYTE, pulEncryptedDataLen *C.CK_ULONG) C.CK_RV {
	if !initialized {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	sess, ok := sessionMgr.Get(uint64(hSession))
	if !ok {
		return C.CKR_SESSION_HANDLE_INVALID
	}
	if sess.EncryptKeyID == "" {
		return C.CKR_OPERATION_NOT_INITIALIZED
	}

	plaintext := C.GoBytes(unsafe.Pointer(pData), C.int(ulDataLen))

	// Try local cache first
	if entry, cached := keyCache.Get(sess.EncryptKeyID); cached {
		ct, iv, err := keycache.EncryptAESGCM(entry, plaintext)
		if err == nil {
			combined := append(iv, ct...)
			if pEncryptedData == nil {
				*pulEncryptedDataLen = C.CK_ULONG(len(combined))
				return C.CKR_OK
			}
			copy((*[1 << 20]byte)(unsafe.Pointer(pEncryptedData))[:len(combined)], combined)
			*pulEncryptedDataLen = C.CK_ULONG(len(combined))
			sess.EncryptKeyID = ""
			return C.CKR_OK
		}
	}

	// Fallback to remote KMS
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ct, iv, err := kmsClient.Wrap(ctx, sess.EncryptKeyID, plaintext)
	if err != nil {
		providerLog.Printf("C_Encrypt: remote wrap failed: %v", err)
		return C.CKR_GENERAL_ERROR
	}
	combined := append(iv, ct...)
	if pEncryptedData == nil {
		*pulEncryptedDataLen = C.CK_ULONG(len(combined))
		return C.CKR_OK
	}
	copy((*[1 << 20]byte)(unsafe.Pointer(pEncryptedData))[:len(combined)], combined)
	*pulEncryptedDataLen = C.CK_ULONG(len(combined))
	sess.EncryptKeyID = ""
	return C.CKR_OK
}

//export C_DecryptInit
func C_DecryptInit(hSession C.CK_SESSION_HANDLE, pMechanism unsafe.Pointer, hKey C.CK_OBJECT_HANDLE) C.CK_RV {
	if !initialized {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	sess, ok := sessionMgr.Get(uint64(hSession))
	if !ok {
		return C.CKR_SESSION_HANDLE_INVALID
	}
	sess.DecryptKeyID = resolveKeyID(sess, uint64(hKey))
	if sess.DecryptKeyID == "" {
		return C.CKR_ARGUMENTS_BAD
	}
	return C.CKR_OK
}

//export C_Decrypt
func C_Decrypt(hSession C.CK_SESSION_HANDLE, pEncryptedData *C.CK_BYTE, ulEncryptedDataLen C.CK_ULONG, pData *C.CK_BYTE, pulDataLen *C.CK_ULONG) C.CK_RV {
	if !initialized {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	sess, ok := sessionMgr.Get(uint64(hSession))
	if !ok {
		return C.CKR_SESSION_HANDLE_INVALID
	}
	if sess.DecryptKeyID == "" {
		return C.CKR_OPERATION_NOT_INITIALIZED
	}

	data := C.GoBytes(unsafe.Pointer(pEncryptedData), C.int(ulEncryptedDataLen))
	if len(data) < 12 {
		return C.CKR_ARGUMENTS_BAD
	}
	iv := data[:12]
	ct := data[12:]

	// Try local cache first
	if entry, cached := keyCache.Get(sess.DecryptKeyID); cached {
		pt, err := keycache.DecryptAESGCM(entry, ct, iv)
		if err == nil {
			if pData == nil {
				*pulDataLen = C.CK_ULONG(len(pt))
				return C.CKR_OK
			}
			copy((*[1 << 20]byte)(unsafe.Pointer(pData))[:len(pt)], pt)
			*pulDataLen = C.CK_ULONG(len(pt))
			sess.DecryptKeyID = ""
			return C.CKR_OK
		}
	}

	// Fallback to remote KMS
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pt, err := kmsClient.Unwrap(ctx, sess.DecryptKeyID, ct, iv)
	if err != nil {
		providerLog.Printf("C_Decrypt: remote unwrap failed: %v", err)
		return C.CKR_GENERAL_ERROR
	}
	if pData == nil {
		*pulDataLen = C.CK_ULONG(len(pt))
		return C.CKR_OK
	}
	copy((*[1 << 20]byte)(unsafe.Pointer(pData))[:len(pt)], pt)
	*pulDataLen = C.CK_ULONG(len(pt))
	sess.DecryptKeyID = ""
	return C.CKR_OK
}

//export C_SignInit
func C_SignInit(hSession C.CK_SESSION_HANDLE, pMechanism unsafe.Pointer, hKey C.CK_OBJECT_HANDLE) C.CK_RV {
	if !initialized {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	sess, ok := sessionMgr.Get(uint64(hSession))
	if !ok {
		return C.CKR_SESSION_HANDLE_INVALID
	}
	sess.SignKeyID = resolveKeyID(sess, uint64(hKey))
	if sess.SignKeyID == "" {
		return C.CKR_ARGUMENTS_BAD
	}
	return C.CKR_OK
}

//export C_Sign
func C_Sign(hSession C.CK_SESSION_HANDLE, pData *C.CK_BYTE, ulDataLen C.CK_ULONG, pSignature *C.CK_BYTE, pulSignatureLen *C.CK_ULONG) C.CK_RV {
	if !initialized {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	sess, ok := sessionMgr.Get(uint64(hSession))
	if !ok {
		return C.CKR_SESSION_HANDLE_INVALID
	}
	if sess.SignKeyID == "" {
		return C.CKR_OPERATION_NOT_INITIALIZED
	}

	data := C.GoBytes(unsafe.Pointer(pData), C.int(ulDataLen))

	// Sign is always remote (asymmetric keys)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sig, err := kmsClient.Sign(ctx, sess.SignKeyID, data, "SHA256withRSA")
	if err != nil {
		providerLog.Printf("C_Sign: remote sign failed: %v", err)
		return C.CKR_GENERAL_ERROR
	}
	if pSignature == nil {
		*pulSignatureLen = C.CK_ULONG(len(sig))
		return C.CKR_OK
	}
	copy((*[1 << 20]byte)(unsafe.Pointer(pSignature))[:len(sig)], sig)
	*pulSignatureLen = C.CK_ULONG(len(sig))
	sess.SignKeyID = ""
	return C.CKR_OK
}

//export C_VerifyInit
func C_VerifyInit(hSession C.CK_SESSION_HANDLE, pMechanism unsafe.Pointer, hKey C.CK_OBJECT_HANDLE) C.CK_RV {
	if !initialized {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	sess, ok := sessionMgr.Get(uint64(hSession))
	if !ok {
		return C.CKR_SESSION_HANDLE_INVALID
	}
	sess.VerifyKeyID = resolveKeyID(sess, uint64(hKey))
	if sess.VerifyKeyID == "" {
		return C.CKR_ARGUMENTS_BAD
	}
	return C.CKR_OK
}

// resolveKeyID maps a PKCS#11 object handle to a KMS key ID.
func resolveKeyID(sess *SessionState, handle uint64) string {
	for _, k := range sess.FindKeys {
		if k.ObjectHandle == handle {
			return k.KeyID
		}
	}
	return ""
}

// main is required for c-shared build mode but not called.
func main() {}
