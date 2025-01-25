// Copyright (c) 2023-2025, El Mostafa IDRASSI.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package goncrypt

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"os"
	"testing"
	"unsafe"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

var (
	verbose           bool
	testLogger        Logger
	rsaPrivateKeyBlob string = "525341320008000003000000000100008000000080000000010001F96884ABE1E3F8F64ECBF80AB27441086D02AFDCCA2A0F08E6256D04C4B5E7AAA48761EF547B35C85A945E5EA82649908DE6770602A877377F93BC5704090BA149EEE3E46B589A02207F20B2FF082DD03E004CED89F91FB15D3EFD0D1DA41E5C1114807862137DD3D90D724B810A4955F5A39CDDA5263DF1110FC882C2824467A607C7A42B250ACA08714A35469DC9F5AE7A13800CCA80272BE360C7E36CA713B249991C536193C89F8872E5424BB8CC1DE5B339E1055ACDB8351F932F46DE1A37AFFE3A1526017DA45C15607C614CDA53173CC23A58C70D12D3DE70AE884D582DFDC845E92E064289860A87533E785DBD1512152628D9F95942F0A8A07A4BE9FA05872A23DB3CBFF8B1F3513DBDEF18A2C923A21A1AAB96104FA9E7FFA51D1A9387F1BB3F71A1BE353B39CD2FE5563B0EE4D027853ABCFFD460FE38985FEBF3A2E546E984BD1BE1D45904462AEC180F3BA5D7AE89852FDDE5AE2F2B5C4C3D1C108F3EF3B98B65B7FC34D13EEB3A039B2C6CD4D6C4ACD751A2BEE0951C04FF77FF5F3C64CE85463AE248513DFF80BCC540F5513A360E994A8D00D45E3761D257C061EEB00E537D034DC1C0B9370661C292963454DCA8ED3445B3B0CDF1874D6393360CB3B23E89A4369E6C8427FE1188A4EFBEA30A126A11FAEED60C10300F3B9A76E451F0F2FECD88B819D23E5E4E5B7B8F4B5850DA373EFD8995E9274FA79F"
)

func TestMain(m *testing.M) {
	flag.BoolVar(&verbose, "verbose", false, "Run tests in verbose mode")
	flag.Parse()

	logFilePath := "ncrypt_test.log"
	logFile, err := os.OpenFile(logFilePath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		testLogger = NewDefaultStdoutLogger(LogLevelError)
		testLogger.Errorf("Log file creation failed: %v", err)
		os.Exit(1)
	}

	if verbose {
		testLogger = NewDefaultFileLogger(LogLevelDebug, logFile)
	} else {
		testLogger = NewDefaultFileLogger(LogLevelNone, logFile)
	}

	err = Initialize(testLogger)
	if err != nil {
		testLogger.Errorf("Initialize failed: %v", err)
		os.Exit(1)
	}
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

func TestIsAlgSupported(t *testing.T) {
	softwareKsp, _, _ := OpenProvider(MsKeyStorageProvider, NcryptSilentFlag)
	defer softwareKsp.Close()

	isAlgSupported, r, err := softwareKsp.IsAlgSupported(NcryptRsaAlgorithm, NcryptSilentFlag)
	require.NoError(t, err)
	require.Equal(t, uint64(0), r)
	require.Equal(t, true, isAlgSupported)
}

func TestCreateAndOpenKey(t *testing.T) {
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
		NcryptSilentFlag,
		NcryptSilentFlag,
	)
	require.NoError(t, err)
	require.Equal(t, uint64(0), r)
	require.NotNil(t, key)
	t.Logf("Key Info")
	t.Logf(" - Name    : %s", key.name)
	t.Logf(" - Alg     : %v", key.alg)
	defer key.Delete(NcryptSilentFlag)

	openedKey, r, err := softwareKsp.OpenKey(
		keyName,
		AtKeyExchange,
		NcryptSilentFlag,
	)
	require.NoError(t, err)
	require.Equal(t, uint64(0), r)
	require.NotNil(t, key)
	require.Equal(t, key.alg, openedKey.alg)
	require.Equal(t, key.name, openedKey.name)
	defer openedKey.Close()
}

/*
func TestCreateAndOpenKeyWithUiPolicy(t *testing.T) {
	softwareKsp, _, _ := OpenProvider(MsKeyStorageProvider, 0)
	defer softwareKsp.Close()

	uuidKeyName, _ := uuid.NewRandom()
	keyName := uuidKeyName.String()

	lengthBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(lengthBytes, 2048)
	keyUsageBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(keyUsageBytes, uint32(NcryptAllowSigningFlag|NcryptAllowDecryptFlag))
	uiPolicy := NcryptUiPolicy{
		Version:      1,
		FriendlyName: keyName,
		Flags:        NcryptUiProtectKeyFlag,
		Description:  "This key requires usage consent and an optional PIN.",
	}
	uiPolicyBytes, _ := uiPolicy.serialize()
	properties := map[NcryptProperty][]byte{
		NcryptLengthProperty:   lengthBytes,
		NcryptKeyUsageProperty: keyUsageBytes,
		NcryptUiPolicyProperty: uiPolicyBytes,
	}

	key, r, err := softwareKsp.CreatePersistedKey(
		NcryptRsaAlgorithm,
		keyName,
		AtKeyExchange,
		properties,
		0,
		0,
		0,
	)
	require.NoError(t, err)
	require.Equal(t, uint64(0), r)
	require.NotNil(t, key)
	t.Logf("Key Info")
	t.Logf(" - Name    : %s", key.name)
	t.Logf(" - Alg     : %v", key.alg)
	defer key.Delete(NcryptSilentFlag)

	openedKey, r, err := softwareKsp.OpenKey(
		keyName,
		AtKeyExchange,
		0,
	)
	require.NoError(t, err)
	require.Equal(t, uint64(0), r)
	require.NotNil(t, key)
	require.Equal(t, key.alg, openedKey.alg)
	require.Equal(t, key.name, openedKey.name)
	defer openedKey.Close()
}
*/

func TestCreateAndExportKey(t *testing.T) {
	softwareKsp, _, _ := OpenProvider(MsKeyStorageProvider, NcryptSilentFlag)
	defer softwareKsp.Close()

	uuidKeyName, _ := uuid.NewRandom()
	keyName := uuidKeyName.String()

	lengthBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(lengthBytes, 2048)
	keyUsageBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(keyUsageBytes, uint32(NcryptAllowSigningFlag|NcryptAllowDecryptFlag))
	exportPolicyBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(exportPolicyBytes, uint32(NcryptAllowExportFlag|NcryptAllowPlaintextExportFlag|NcryptAllowArchivingFlag|NcryptAllowPlaintextArchivingFlag))
	properties := map[NcryptProperty][]byte{
		NcryptLengthProperty:       lengthBytes,
		NcryptKeyUsageProperty:     keyUsageBytes,
		NcryptExportPolicyProperty: exportPolicyBytes,
	}

	key, r, err := softwareKsp.CreatePersistedKey(
		NcryptRsaAlgorithm,
		keyName,
		AtKeyExchange,
		properties,
		NcryptSilentFlag,
		NcryptSilentFlag,
		NcryptSilentFlag,
	)
	require.NoError(t, err)
	require.Equal(t, uint64(0), r)
	require.NotNil(t, key)
	t.Logf("Key Info")
	t.Logf(" - Name    : %s", key.name)
	t.Logf(" - Alg     : %v", key.alg)
	defer key.Delete(NcryptSilentFlag)

	blob, r, err := key.Export(Key{}, NcryptRsaPrivateBlob, nil, NcryptSilentFlag)
	require.NoError(t, err)
	require.Equal(t, uint64(0), r)
	require.NotNil(t, key)
	t.Logf("Key Blob: %X", blob)
}

func TestImportKey(t *testing.T) {
	softwareKsp, _, _ := OpenProvider(MsKeyStorageProvider, NcryptSilentFlag)
	defer softwareKsp.Close()

	rsaPrivateKeyBlobBytes, _ := hex.DecodeString(rsaPrivateKeyBlob)

	key, r, err := softwareKsp.ImportKey(
		Key{},
		NcryptRsaPrivateBlob,
		nil,
		rsaPrivateKeyBlobBytes,
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

func TestEnumKeys(t *testing.T) {
	softwareKsp, _, _ := OpenProvider(MsKeyStorageProvider, NcryptSilentFlag)
	defer softwareKsp.Close()

	uuidKeyName, _ := uuid.NewRandom()
	keyName := uuidKeyName.String()
	lengthBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(lengthBytes, 2048)
	keyUsageBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(keyUsageBytes, uint32(NcryptAllowSigningFlag|NcryptAllowDecryptFlag))
	exportPolicyBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(exportPolicyBytes, uint32(NcryptAllowExportFlag|NcryptAllowPlaintextExportFlag|NcryptAllowArchivingFlag|NcryptAllowPlaintextArchivingFlag))
	properties := map[NcryptProperty][]byte{
		NcryptLengthProperty:       lengthBytes,
		NcryptKeyUsageProperty:     keyUsageBytes,
		NcryptExportPolicyProperty: exportPolicyBytes,
	}

	key, r, err := softwareKsp.CreatePersistedKey(
		NcryptRsaAlgorithm,
		keyName,
		AtKeyExchange,
		properties,
		NcryptSilentFlag,
		NcryptSilentFlag,
		NcryptSilentFlag,
	)
	require.NoError(t, err)
	require.Equal(t, uint64(0), r)
	require.NotNil(t, key)
	defer key.Delete(NcryptSilentFlag)

	bKeyFound := false
	keysInfo, r, err := softwareKsp.EnumKeys("", NcryptSilentFlag)
	require.NoError(t, err)
	require.Equal(t, uint64(0), r)
	if len(keysInfo) == 0 {
		t.Fatal("No keys found")
	}
	for i, keyInfo := range keysInfo {
		if keyInfo.Name == key.name {
			bKeyFound = true
			t.Logf("Key Info %d", i+1)
			t.Logf(" - Name    : %s", keyInfo.Name)
			t.Logf(" - Alg     : %v", keyInfo.Alg)
			t.Logf(" - KeySpec : %s", keyInfo.LegacyKeySpec.String())
			t.Logf(" - Flags   : 0x%.8X", keyInfo.Flags)
			break
		}
	}
	require.Equal(t, true, bKeyFound)
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
		NcryptSilentFlag,
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
		NcryptSilentFlag,
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
