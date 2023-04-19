package goncrypt

import (
	"crypto/sha256"
	"encoding/binary"
	"flag"
	"os"
	"testing"
	"unsafe"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

var (
	verbose    bool
	testLogger Logger
)

func TestMain(m *testing.M) {
	flag.BoolVar(&verbose, "verbose", false, "Run tests in verbose mode")
	flag.Parse()
	if verbose {
		testLogger = NewDefaultLogger(LogLevelDebug)
	} else {
		testLogger = NewDefaultLogger(LogLevelNone)
	}

	Initialize(testLogger)
	defer Finalize()

	exitCode := m.Run()
	os.Exit(exitCode)
}

func TestEnumProviders(t *testing.T) {
	provsInfo, r, err := EnumProviders(NcryptSilentFlag)
	require.NoError(t, err)
	require.Equal(t, uint64(0), r)
	require.NotNil(t, provsInfo)
	if len(provsInfo) == 0 {
		t.Fatal("No providers found")
	}
	for _, provInfo := range provsInfo {
		t.Log(provInfo.Name)
	}
}

func TestOpenProvider(t *testing.T) {
	t.Run("SoftwareKSP", func(t *testing.T) {
		provider, r, err := OpenProvider(MsKeyStorageProvider, NcryptSilentFlag)
		require.NoError(t, err)
		require.Equal(t, uint64(0), r)
		require.NotEqual(t, invalidHandleValue, provider.handle)
		require.Equal(t, MsKeyStorageProvider, provider.name)
		defer provider.Close()
	})
}

func TestGetProviderProperty(t *testing.T) {
	softwareKsp, _, _ := OpenProvider(MsKeyStorageProvider, NcryptSilentFlag)
	defer softwareKsp.Close()

	t.Run("SoftwareKSP", func(t *testing.T) {
		property, r, err := softwareKsp.GetProperty(NcryptImplTypeProperty, NcryptSilentFlag)
		require.NoError(t, err)
		require.Equal(t, uint64(0), r)
		require.NotNil(t, property)
		require.Equal(t, 4, len(property))

		propertyUint32, err := bytesToUint32(property, true)
		require.NoError(t, err)

		implType := NcryptImplTypePropertyFlag(propertyUint32)
		t.Logf("Impl type: %s", implType.String())
	})
}

func TestEnumAlgorithms(t *testing.T) {
	softwareKsp, _, _ := OpenProvider(MsKeyStorageProvider, NcryptSilentFlag)
	defer softwareKsp.Close()

	allAlgOps := NcryptCipherOperation | NcryptHashOperation | NcryptAsymmetricEncryptionOperation | NcryptSecretAgreementOperation | NcryptSignatureOperation | NcryptRngOperation | NcryptKeyDerivationOperation
	algsInfo, r, err := softwareKsp.EnumAlgorithms(allAlgOps, NcryptSilentFlag)
	require.NoError(t, err)
	require.Equal(t, uint64(0), r)
	require.NotNil(t, algsInfo)
	if len(algsInfo) == 0 {
		t.Fatal("No algorithms found")
	}
	for i, algInfo := range algsInfo {
		t.Logf("Alg Info %d", i+1)
		t.Logf(" - Name  : %s", algInfo.Name)
		t.Logf(" - Class : %s", algInfo.Class.String())
		t.Logf(" - Ops   : %s", algInfo.AlgOperations.String())
		t.Logf(" - Flags : 0x%.8X", algInfo.Flags)
	}
}

func TestEnumKeys(t *testing.T) {
	softwareKsp, _, _ := OpenProvider(MsKeyStorageProvider, NcryptSilentFlag)
	defer softwareKsp.Close()

	keysInfo, r, err := softwareKsp.EnumKeys("", NcryptSilentFlag)
	require.NoError(t, err)
	require.Equal(t, uint64(0), r)
	require.NotNil(t, keysInfo)
	if len(keysInfo) == 0 {
		t.Fatal("No keys found")
	}
	for i, keyInfo := range keysInfo {
		t.Logf("Key Info %d", i+1)
		t.Logf(" - Name    : %s", keyInfo.Name)
		t.Logf(" - Alg     : %v", keyInfo.Alg)
		t.Logf(" - KeySpec : %s", keyInfo.LegacyKeySpec.String())
		t.Logf(" - Flags   : 0x%.8X", keyInfo.Flags)
	}
}

func TestCreateKey(t *testing.T) {
	softwareKsp, _, _ := OpenProvider(MsKeyStorageProvider, NcryptSilentFlag)
	defer softwareKsp.Close()

	uuidKeyName, _ := uuid.NewRandom()
	keyName := uuidKeyName.String()

	lengthBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(lengthBytes, 2048)
	keyUsageBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(keyUsageBytes, uint32(NcryptAllowSigningFlag|NcryptAllowDecryptFlag))
	properties := map[NcryptProperty][]byte{
		NcryptLengthProperty:   lengthBytes,
		NcryptKeyUsageProperty: keyUsageBytes,
	}

	key, r, err := softwareKsp.CreatePersistedKey(
		NcryptRsaAlgorithm,
		keyName,
		AtKeyExchange,
		properties,
		NcryptSilentFlag,
	)
	require.NoError(t, err)
	require.Equal(t, uint64(0), r)
	require.NotNil(t, key)
	t.Logf("Key Info")
	t.Logf(" - Name    : %s", key.name)
	t.Logf(" - Alg     : %v", key.alg)
	defer key.Delete(NcryptSilentFlag)
}

func TestSignVerify(t *testing.T) {
	softwareKsp, _, _ := OpenProvider(MsKeyStorageProvider, NcryptSilentFlag)
	defer softwareKsp.Close()

	uuidKeyName, _ := uuid.NewRandom()
	keyName := uuidKeyName.String()

	lengthBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(lengthBytes, 2048)
	keyUsageBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(keyUsageBytes, uint32(NcryptAllowSigningFlag|NcryptAllowDecryptFlag))
	properties := map[NcryptProperty][]byte{
		NcryptLengthProperty:   lengthBytes,
		NcryptKeyUsageProperty: keyUsageBytes,
	}

	key, r, err := softwareKsp.CreatePersistedKey(
		NcryptRsaAlgorithm,
		keyName,
		AtKeyExchange,
		properties,
		NcryptSilentFlag,
	)
	require.NoError(t, err)
	require.Equal(t, uint64(0), r)
	require.NotNil(t, key)
	defer key.Delete(NcryptSilentFlag)

	sha256Hash := sha256.New()
	sha256Hash.Write([]byte{0x00, 0x00})
	hash := sha256Hash.Sum(nil)
	paddingInfo := BcryptPkcs1PaddingInfo{}
	paddingInfo.AlgId, _ = windows.UTF16PtrFromString(string(NcryptSha256Algorithm))
	signature, r, err := key.Sign(unsafe.Pointer(&paddingInfo), hash, NcryptPadPkcs1Flag|NcryptSilentFlag)
	require.NoError(t, err)
	require.Equal(t, uint64(0), r)
	require.NotNil(t, signature)

	isVerified, r, err := key.Verify(unsafe.Pointer(&paddingInfo), hash, signature, NcryptPadPkcs1Flag|NcryptSilentFlag)
	require.NoError(t, err)
	require.Equal(t, uint64(0), r)
	require.Equal(t, true, isVerified)
}

func TestEncryptDecrypt(t *testing.T) {
	softwareKsp, _, _ := OpenProvider(MsKeyStorageProvider, NcryptSilentFlag)
	defer softwareKsp.Close()

	uuidKeyName, _ := uuid.NewRandom()
	keyName := uuidKeyName.String()

	lengthBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(lengthBytes, 2048)
	keyUsageBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(keyUsageBytes, uint32(NcryptAllowSigningFlag|NcryptAllowDecryptFlag))
	properties := map[NcryptProperty][]byte{
		NcryptLengthProperty:   lengthBytes,
		NcryptKeyUsageProperty: keyUsageBytes,
	}

	key, r, err := softwareKsp.CreatePersistedKey(
		NcryptRsaAlgorithm,
		keyName,
		AtKeyExchange,
		properties,
		NcryptSilentFlag,
	)
	require.NoError(t, err)
	require.Equal(t, uint64(0), r)
	require.NotNil(t, key)
	defer key.Delete(NcryptSilentFlag)

	sha256Hash := sha256.New()
	sha256Hash.Write([]byte{0x00, 0x00})
	hash := sha256Hash.Sum(nil)
	paddingInfo := BcryptPkcs1PaddingInfo{}
	paddingInfo.AlgId, _ = windows.UTF16PtrFromString(string(NcryptSha256Algorithm))
	encryptedData, r, err := key.Encrypt(hash, unsafe.Pointer(&paddingInfo), NcryptPadPkcs1Flag|NcryptSilentFlag)
	require.NoError(t, err)
	require.Equal(t, uint64(0), r)
	require.NotNil(t, encryptedData)

	decryptedData, r, err := key.Decrypt(encryptedData, unsafe.Pointer(&paddingInfo), NcryptPadPkcs1Flag|NcryptSilentFlag)
	require.NoError(t, err)
	require.Equal(t, uint64(0), r)
	require.Equal(t, hash, decryptedData)
}
