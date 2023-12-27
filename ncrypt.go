package goncrypt

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"path/filepath"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

//////////////////////////////////////////////////////////////////////////////////////
// Misc.
//////////////////////////////////////////////////////////////////////////////////////

// utf16BytesToString transforms a []byte which contains a wide char string in LE
// into its []uint16 corresponding representation,
// then returns the UTF-8 encoding of the UTF-16 sequence,
// with a terminating NUL removed. If after converting the []byte into
// a []uint16, there is a NUL uint16, the conversion to string stops
// at that NUL uint16.
func utf16BytesToString(buf []byte) (string, error) {

	if len(buf)%2 != 0 {
		return "", fmt.Errorf("input is not a valid byte representation of a wide char string in LE")
	}
	b := make([]uint16, len(buf)/2)

	// LPCSTR (Windows' representation of utf16) is always little endian.
	if err := binary.Read(bytes.NewReader(buf), binary.LittleEndian, b); err != nil {
		return "", err
	}
	return windows.UTF16ToString(b), nil
}

// utf16ToString transforms a []utf16 which contains a wide char string in LE
// into its UTF-8 encoding representation, with a terminating NUL removed.
// The conversion stops at the first encountered NUL uint16.
func utf16ToString(buf []uint16) (string, error) {
	return windows.UTF16ToString(buf), nil
}

// utf16PtrToString transforms a *utf16 which contains a wide char string in LE
// into its UTF-8 encoding representation, with a terminating NUL removed.
// The conversion stops at the first encountered NUL uint16.
func utf16PtrToString(buf *uint16) string {
	return windows.UTF16PtrToString(buf)
}

// stringToUtf16Ptr returns the UTF-16 encoding of the UTF-8 string
// str, with a terminating NUL added. If str contains a NUL byte at any
// location, it returns (nil, EINVAL).
func stringToUtf16(str string) ([]uint16, error) {
	if str == "" {
		return nil, nil
	}
	return windows.UTF16FromString(str)
}

// stringToUtf16Ptr returns the UTF-16 encoding of the UTF-8 string
// str, with a terminating NUL added. If str contains a NUL byte at any
// location, it returns (nil, EINVAL).
func stringToUtf16Ptr(str string) (*uint16, error) {
	if str == "" {
		return nil, nil
	}
	return windows.UTF16PtrFromString(str)
}

// bytesToUtf16Ptr returns the UTF-16 encoding of the UTF-8 string
// contained in buf as a byte array, with a terminating NUL added.
// If str contains a NUL byte at any location, it returns (nil, EINVAL).
func bytesToUtf16Ptr(buf []byte) (*uint16, error) {
	str := string(buf)
	return stringToUtf16Ptr(str)
}

// bytesToUtf16 returns the UTF-16 encoding of the UTF-8 string
// contained in buf as a byte array, with a terminating NUL added.
// If str contains a NUL byte at any location, it returns (nil, EINVAL).
func bytesToUtf16(buf []byte) ([]uint16, error) {
	str := string(buf)
	return stringToUtf16(str)
}

// stringToUtf16Bytes returns the UTF-16 encoding of the UTF-8 string
// str, as a byte array with a terminating NUL added. If str contains a NUL byte at any
// location, it returns (nil, EINVAL).
func stringToUtf16Bytes(str string) ([]byte, error) {
	if str == "" {
		return nil, nil
	}
	utf16Str, err := windows.UTF16FromString(str)
	if err != nil {
		return nil, err
	}
	bytesStr := make([]byte, len(utf16Str)*2)
	j := 0
	for _, utf16 := range utf16Str {
		b := make([]byte, 2)
		// LPCSTR (Windows' representation of utf16) is always little endian.
		binary.LittleEndian.PutUint16(b, utf16)
		bytesStr[j] = b[0]
		bytesStr[j+1] = b[1]
		j += 2
	}
	return bytesStr, nil
}

// stringToUtf16String returns the UTF-16 encoding of the UTF-8 string
// str, with a terminating NUL added. If str contains a NUL byte at any
// location, it returns (nil, EINVAL).
func stringToUtf16String(str string) ([]uint16, error) {
	if str == "" {
		return nil, nil
	}
	utf16Str, err := windows.UTF16FromString(str)
	if err != nil {
		return nil, err
	}
	return utf16Str, nil
}

func bytesToUint32(input []byte, isLittleEndian bool) (ret uint32, err error) {
	if len(input) == 4 {
		if isLittleEndian {
			ret = binary.LittleEndian.Uint32(input)
		} else {
			ret = binary.BigEndian.Uint32(input)
		}
	} else {
		err = fmt.Errorf("unexpected input length: expected %d, got %d", 4, len(input))
	}

	return
}

//////////////////////////////////////////////////////////////////////////////////////
// Some BCrypt header content.
// From C:\Program Files (x86)\Windows Kits\10\Include\10.0.19041.0\shared\bcrypt.h
//////////////////////////////////////////////////////////////////////////////////////

type HcryptProv uintptr
type HcryptKey uintptr
type HcryptHash uintptr

const (
	// Properties of secret agreement algorithms
	BcryptGlobalParameters string = "SecretAgreementParam"
	BcryptPrivateey        string = "PrivKeyVal"

	// Property Strings for DH
	BcryptDhParameters string = "DHParameters"

	// Property Strings for DSA
	BcryptDsaParameters string = "DSAParameters"

	//Property Strings for ECC
	BcryptEccParameters    string = "ECCParameters"
	BcryptEccCurveName     string = "ECCCurveName"
	BcryptEccCurveNameList string = "ECCCurveNameList"
)

//
// DeriveKey KDF Types
//

type BcryptKdfType string

const (
	BcryptKdfHash   BcryptKdfType = "HASH"
	BcryptKdfHmac   BcryptKdfType = "HMAC"
	BcryptKdfTlsPrf BcryptKdfType = "TLS_PRF"

	BcryptKdfSp80056aConcat BcryptKdfType = "SP800_56A_CONCAT"
	BcryptKdfRawSecret      BcryptKdfType = "TRUNCATE"

	BcryptKdfHkdf BcryptKdfType = "HKDF"
)

//
// BCrypt structures
//

type BcryptBuffer struct { // BCryptBuffer
	BufferLen  uint32 // Length of buffer, in bytes
	BufferType uint32 // Buffer type
	Buffer     *byte  // Pointer to buffer
}
type BcryptBufferDesc struct { // BCryptBufferDesc
	Version    uint32        // Version number
	BuffersLen uint32        // Number of buffers
	Buffers    *BcryptBuffer // Pointer to array of buffers
}

type BcryptVersion uint32

const (
	BcryptBufferVersion          BcryptVersion = 0
	BcryptEccFullKeyBlobVersion1 BcryptVersion = 0x1
	BcryptKeyDataBlobVersion1    BcryptVersion = 0x1
)

type BcryptKeyBlobType string

const (
	BcryptPublicKeyBlob  BcryptKeyBlobType = "PUBLICBLOB"
	BcryptPrivateKeyBlob BcryptKeyBlobType = "PRIVATEBLOB"

	// The BCRYPT_RSAPUBLIC_BLOB and BCRYPT_RSAPRIVATE_BLOB blob types are used
	// to transport plaintext RSA keys. These blob types will be supported by
	// all RSA primitive providers.
	// The BCRYPT_RSAPRIVATE_BLOB includes the following values:
	// Public Exponent
	// Modulus
	// Prime1
	// Prime2
	BcryptRsaPublicBlob  BcryptKeyBlobType = "RSAPUBLICBLOB"
	BcryptRsaPrivateBlob BcryptKeyBlobType = "RSAPRIVATEBLOB"
	// The BCRYPT_RSAFULLPRIVATE_BLOB blob type is used to transport
	// plaintext private RSA keys.  It includes the following values:
	// Public Exponent
	// Modulus
	// Prime1
	// Prime2
	// Private Exponent mod (Prime1 - 1)
	// Private Exponent mod (Prime2 - 1)
	// Inverse of Prime2 mod Prime1
	// PrivateExponent
	BcryptRsaFullPrivateBlob   BcryptKeyBlobType = "RSAFULLPRIVATEBLOB"
	BcryptLegacyRsaPublicBlob  BcryptKeyBlobType = "CAPIPUBLICBLOB"
	BcryptLegacyRsaPrivateBlob BcryptKeyBlobType = "CAPIPRIVATEBLOB"

	// The BCRYPT_ECCPUBLIC_BLOB and BCRYPT_ECCPRIVATE_BLOB blob types are used
	// to transport plaintext ECC keys. These blob types will be supported by
	// all ECC primitive providers.
	BcryptEccPublicBlob      BcryptKeyBlobType = "ECCPUBLICBLOB"
	BcryptEccPrivateBlob     BcryptKeyBlobType = "ECCPRIVATEBLOB"
	BcryptEccFullPublicBlob  BcryptKeyBlobType = "ECCFULLPUBLICBLOB"
	BcryptEccFullPrivateBlob BcryptKeyBlobType = "ECCFULLPRIVATEBLOB"

	BcryptSslEccPublicBlob BcryptKeyBlobType = "SSLECCPUBLICBLOB"

	// The BCRYPT_DH_PUBLIC_BLOB and BCRYPT_DH_PRIVATE_BLOB blob types are used
	// to transport plaintext DH keys. These blob types will be supported by
	// all DH primitive providers.
	BcryptDhPublicBlob        BcryptKeyBlobType = "DHPUBLICBLOB"
	BcryptDhPrivateBlob       BcryptKeyBlobType = "DHPRIVATEBLOB"
	BcryptLegacyDhPublicBlob  BcryptKeyBlobType = "CAPIDHPUBLICBLOB"
	BcryptLegacyDhPrivateBlob BcryptKeyBlobType = "CAPIDHPRIVATEBLOB"

	// The BCRYPT_DSA_PUBLIC_BLOB and BCRYPT_DSA_PRIVATE_BLOB blob types are used
	// to transport plaintext DSA keys. These blob types will be supported by
	// all DSA primitive providers.
	BcryptDsaPublicBlob          BcryptKeyBlobType = "DSAPUBLICBLOB"
	BcryptDsaPrivateBlob         BcryptKeyBlobType = "DSAPRIVATEBLOB"
	BcryptLegacyDsaPublicBlob    BcryptKeyBlobType = "CAPIDSAPUBLICBLOB"
	BcryptLegacyDsaPrivateBlob   BcryptKeyBlobType = "CAPIDSAPRIVATEBLOB"
	BcryptLegacyDsaV2PublicBlob  BcryptKeyBlobType = "V2CAPIDSAPUBLICBLOB"
	BcryptLegacyDsaV2PrivateBlob BcryptKeyBlobType = "V2CAPIDSAPRIVATEBLOB"
)

type BcryptMagic uint32

const (
	BcryptRsaPublicMagic      BcryptMagic = 0x31415352 // RSA1
	BcryptRsaPrivateMagic     BcryptMagic = 0x32415352 // RSA2
	BcryptRsaFullPrivateMagic BcryptMagic = 0x33415352 // RSA3

	BcryptEcdhPublicP256Magic     BcryptMagic = 0x314B4345 // ECK1
	BcryptEcdhPrivateP256Magic    BcryptMagic = 0x324B4345 // ECK2
	BcryptEcdhPublicP384Magic     BcryptMagic = 0x334B4345 // ECK3
	BcryptEcdhPrivateP384Magic    BcryptMagic = 0x344B4345 // ECK4
	BcryptEcdhPublicP521Magic     BcryptMagic = 0x354B4345 // ECK5
	BcryptEcdhPrivateP521Magic    BcryptMagic = 0x364B4345 // ECK6
	BcryptEcdhPublicGenericMagic  BcryptMagic = 0x504B4345 // ECKP
	BcryptEcdhPrivateGenericMagic BcryptMagic = 0x564B4345 // ECKV

	BcryptEcdsaPublicP256Magic     BcryptMagic = 0x31534345 // ECS1
	BcryptEcdsaPrivateP256Magic    BcryptMagic = 0x32534345 // ECS2
	BcryptEcdsaPublicP384Magic     BcryptMagic = 0x33534345 // ECS3
	BcryptEcdsaPrivateP384Magic    BcryptMagic = 0x34534345 // ECS4
	BcryptEcdsaPublicP521Magic     BcryptMagic = 0x35534345 // ECS5
	BcryptEcdsaPrivateP521Magic    BcryptMagic = 0x36534345 // ECS6
	BcryptEcdsaPublicGenericMagic  BcryptMagic = 0x50444345 // ECDP
	BcryptEcdsaPrivateGenericMagic BcryptMagic = 0x56444345 // ECDV

	BcryptDhPublicMagic  BcryptMagic = 0x42504844 // DHPB
	BcryptDhPrivateMagic BcryptMagic = 0x56504844 // DHPV

	BcryptDsaPublicMagic    BcryptMagic = 0x42505344 // DSPB
	BcryptDsaPrivateMagic   BcryptMagic = 0x56505344 // DSPV
	BcryptDsaPublicMagicV2  BcryptMagic = 0x32425044 // DPB2
	BcryptDsaPrivateMagicV2 BcryptMagic = 0x32565044 // DPV2

	BcryptDhParametersMagic BcryptMagic = 0x4d504844 // DHPM

	BcryptKeyDataBlobMagic BcryptMagic = 0x4d42444b // Key Data Blob Magic (KDBM)

	BcryptDsaParametersMagic   BcryptMagic = 0x4d505344 // DSPM
	BcryptDsaParametersMagicV2 BcryptMagic = 0x324d5044 // DPM2

	BcryptEccParametersMagic BcryptMagic = 0x50434345 // ECCP
)

// enum ECC_CURVE_TYPE_ENUM
type BcryptEccCurveType int32

const (
	BcryptEccPrimeShortWeierstrassCurve BcryptEccCurveType = 0x1
	BcryptEccPrimeTwistedEdwardsCurve   BcryptEccCurveType = 0x2
	BcryptEccPrimeMontgomeryCurve       BcryptEccCurveType = 0x3
)

// enum ECC_CURVE_ALG_ID_ENUM
type BcryptEccCurveAlgId int32

const (
	BcryptNoCurveGenerationAlgId BcryptEccCurveAlgId = 0x0
)

// enum HASHALGORITHM_ENUM
type BcryptHashAlgorithm int32

const (
	DsaHashAlgorithmSha1 BcryptHashAlgorithm = iota
	DsaHashAlgorithmSha256
	DsaHashAlgorithmSha512
)

// enum DSAFIPSVERSION_ENUM
type BcryptDsaFipsVersion int32

const (
	DsaFips1862 BcryptDsaFipsVersion = iota
	DsaFips1863
)

//
// ECC Curve Names
//

type BcryptEccCurve string

const (
	BcryptEccCurveBrainpoolP160R1 BcryptEccCurve = "brainpoolP160r1"
	BcryptEccCurveBrainpoolP160T1 BcryptEccCurve = "brainpoolP160t1"
	BcryptEccCurveBrainpoolP192R1 BcryptEccCurve = "brainpoolP192r1"
	BcryptEccCurveBrainpoolP192T1 BcryptEccCurve = "brainpoolP192t1"
	BcryptEccCurveBrainpoolP224R1 BcryptEccCurve = "brainpoolP224r1"
	BcryptEccCurveBrainpoolP224T1 BcryptEccCurve = "brainpoolP224t1"
	BcryptEccCurveBrainpoolP256R1 BcryptEccCurve = "brainpoolP256r1"
	BcryptEccCurveBrainpoolP256T1 BcryptEccCurve = "brainpoolP256t1"
	BcryptEccCurveBrainpoolP320R1 BcryptEccCurve = "brainpoolP320r1"
	BcryptEccCurveBrainpoolP320T1 BcryptEccCurve = "brainpoolP320t1"
	BcryptEccCurveBrainpoolP384R1 BcryptEccCurve = "brainpoolP384r1"
	BcryptEccCurveBrainpoolP384T1 BcryptEccCurve = "brainpoolP384t1"
	BcryptEccCurveBrainpoolP512R1 BcryptEccCurve = "brainpoolP512r1"
	BcryptEccCurveBrainpoolP512T1 BcryptEccCurve = "brainpoolP512t1"
	BcryptEccCurve25519           BcryptEccCurve = "curve25519"
	BcryptEccCurveEc192Wapi       BcryptEccCurve = "ec192wapi"
	BcryptEccCurveNistP192        BcryptEccCurve = "nistP192"
	BcryptEccCurveNistP224        BcryptEccCurve = "nistP224"
	BcryptEccCurveNistP256        BcryptEccCurve = "nistP256"
	BcryptEccCurveNistP384        BcryptEccCurve = "nistP384"
	BcryptEccCurveNistP521        BcryptEccCurve = "nistP521"
	BcryptEccCurveNumsp256T1      BcryptEccCurve = "numsP256t1"
	BcryptEccCurveNumsp384T1      BcryptEccCurve = "numsP384t1"
	BcryptEccCurveNumsp512T1      BcryptEccCurve = "numsP512t1"
	BcryptEccCurveSecp160K1       BcryptEccCurve = "secP160k1"
	BcryptEccCurveSecp160R1       BcryptEccCurve = "secP160r1"
	BcryptEccCurveSecp160R2       BcryptEccCurve = "secP160r2"
	BcryptEccCurveSecp192K1       BcryptEccCurve = "secP192k1"
	BcryptEccCurveSecp192R1       BcryptEccCurve = "secP192r1"
	BcryptEccCurveSecp224K1       BcryptEccCurve = "secP224r1"
)

//
// Structures used to represent key blobs
//

type BcryptKeyBlob struct {
	Magic BcryptMagic
}

type BcryptRsaKeyBlob struct {
	Magic        BcryptMagic
	BitLength    uint32
	PublicExpLen uint32
	ModulusLen   uint32
	Prime1Len    uint32
	Prime2Len    uint32
}

type BcryptEccKeyBlob struct {
	Magic  BcryptMagic
	KeyLen uint32
}
type BcryptSslEccKeyBlob struct {
	CurveType BcryptEccCurveType
	KeyLen    uint32
}

// The full version contains the curve parameters as well
// as the public and potentially private exponent.
type BcryptEccFullKeyBlob struct {
	Magic                BcryptMagic
	Version              uint32              // Version of the structure
	CurveType            BcryptEccCurveType  // Supported curve types.
	CurveGenerationAlgId BcryptEccCurveAlgId // For X.592 verification purposes, if we include Seed we will need to include the algorithm ID.
	FieldLengthLen       uint32              // Byte length of the fields P, A, B, X, Y.
	SubgroupOrderLen     uint32              // Byte length of the subgroup.
	CofactorLen          uint32              // Byte length of cofactor of G in E.
	SeedLen              uint32              // Byte length of the seed used to generate the curve.
	//P[cbFieldLength]              Prime specifying the base field.
	//A[cbFieldLength]              Coefficient A of the equation y^2 = x^3 + A*x + B mod p
	//B[cbFieldLength]              Coefficient B of the equation y^2 = x^3 + A*x + B mod p
	//Gx[cbFieldLength]             X-coordinate of the base point.
	//Gy[cbFieldLength]             Y-coordinate of the base point.
	//n[cbSubgroupOrder]            Order of the group generated by G = (x,y)
	//h[cbCofactor]                 Cofactor of G in E.
	//S[cbSeed]                     Seed of the curve.
	//Qx[cbFieldLength]             X-coordinate of the public point.
	//Qy[cbFieldLength]             Y-coordinate of the public point.
	//d[cbSubgroupOrder]            Private key.  Not always present.
}

type BcryptDhKeyBlob struct {
	Magic  BcryptMagic
	KeyLen uint32
}
type BcryptDhParameterHeader struct {
	Length uint32
	Magic  BcryptMagic
	KeyLen uint32
}

type BcryptDsaKeyBlob struct {
	Magic  BcryptMagic
	KeyLen uint32
	Count  [4]byte
	Seed   [20]byte
	Q      [20]byte
}
type BcryptDsaKeyBlobV2 struct {
	Magic           BcryptMagic
	KeyLen          uint32
	HashAlgorithm   BcryptHashAlgorithm
	StandardVersion BcryptDsaFipsVersion
	SeedLen         uint32
	GroupSize       uint32
	Count           [4]byte
}

type BcryptKeyDataBlobHeader struct {
	Magic      BcryptMagic
	Version    uint32
	KeyDataLen uint32
}

type BcryptDsaParameterHeader struct {
	Length uint32
	Magic  BcryptMagic
	KeyLen uint32
	Count  [4]byte
	Seed   [20]byte
	Q      [20]byte
}
type BcryptDsaParameterHeaderV2 struct {
	Length          uint32
	Magic           BcryptMagic
	KeyLen          uint32
	HashAlgorithm   BcryptHashAlgorithm
	StandardVersion BcryptDsaFipsVersion
	SeedLen         uint32
	GroupSize       uint32
	Count           [4]byte
}

type BcryptEccCurveNames struct {
	EccCurveNamesLen uint32
	EccCurveNames    **uint16
}

type BcryptPkcs1PaddingInfo struct {
	AlgId *uint16
}

type BcryptPssPaddingInfo struct {
	AlgId   *uint16
	SaltLen uint32
}

type BcryptOaepPaddingInfo struct {
	AlgId    *uint16
	Label    *byte
	LabelLen uint32
}

//////////////////////////////////////////////////////////////////////////////////////
// NCrypt header content.
// From C:\Program Files (x86)\Windows Kits\10\Include\10.0.19041.0\um\ncrypt.h
//////////////////////////////////////////////////////////////////////////////////////

const (
	//
	// Maximum length of Key name, in characters
	//
	NcryptMaxKeyNameLength = 512

	//
	// Maximum length of Algorithm name, in characters
	//
	NcryptMaxAlgIdLength = 512

	//
	// Key name for sealing
	//
	TpmRsaSrkSealKey = "MICROSOFT_PCP_KSP_RSA_SEAL_KEY_3BD1C4BF-004E-4E2F-8A4D-0BF633DCB074"
)

//
// Microsoft built-in providers
//

const (
	MsKeyStorageProvider          string = "Microsoft Software Key Storage Provider"
	MsSmartCardKeyStorageProvider string = "Microsoft Smart Card Key Storage Provider"
	MsPlatformKeyStorageProvider  string = "Microsoft Platform Crypto Provider"
	MsNgcKeyStorageProvider       string = "Microsoft Passport Key Storage Provider"
)

//
// Common algorithm identifiers
//

type NcryptAlgorithm string

const (
	NcryptRsaAlgorithm             NcryptAlgorithm = "RSA"
	NcryptRsaSignAlgorithm         NcryptAlgorithm = "RSA_SIGN"
	NcryptDhAlgorithm              NcryptAlgorithm = "DH"
	NcryptDsaAlgorithm             NcryptAlgorithm = "DSA"
	NcryptMd2Algorithm             NcryptAlgorithm = "MD2"
	NcryptMd4Algorithm             NcryptAlgorithm = "MD4"
	NcryptMd5Algorithm             NcryptAlgorithm = "MD5"
	NcryptSha1Algorithm            NcryptAlgorithm = "SHA1"
	NcryptSha256Algorithm          NcryptAlgorithm = "SHA256"
	NcryptSha384Algorithm          NcryptAlgorithm = "SHA384"
	NcryptSha512Algorithm          NcryptAlgorithm = "SHA512"
	NcryptEcdsaP256Algorithm       NcryptAlgorithm = "ECDSA_P256"
	NcryptEcdsaP384Algorithm       NcryptAlgorithm = "ECDSA_P384"
	NcryptEcdsaP521Algorithm       NcryptAlgorithm = "ECDSA_P521"
	NcryptEcdhP256Algorithm        NcryptAlgorithm = "ECDH_P256"
	NcryptEcdhP384Algorithm        NcryptAlgorithm = "ECDH_P384"
	NcryptEcdhP521Algorithm        NcryptAlgorithm = "ECDH_P521"
	NcryptAesAlgorithm             NcryptAlgorithm = "AES"
	NcryptRc2Algorithm             NcryptAlgorithm = "RC2"
	Ncrypt3desAlgorithm            NcryptAlgorithm = "3DES"
	NcryptDesAlgorithm             NcryptAlgorithm = "DES"
	NcryptDesxAlgorithm            NcryptAlgorithm = "DESX"
	Ncrypt3des112Algorithm         NcryptAlgorithm = "3DES_112"
	NcryptSp800108CtrHmacAlgorithm NcryptAlgorithm = "SP800_108_CTR_HMAC"
	NcryptSp80056aConcatAlgorithm  NcryptAlgorithm = "SP800_56A_CONCAT"
	NcryptPbkdf2Algorithm          NcryptAlgorithm = "PBKDF2"
	NcryptCapiKdfAlgorithm         NcryptAlgorithm = "CAPI_KDF"
	NcryptEcdsaAlgorithm           NcryptAlgorithm = "ECDSA"
	NcryptKeyStorageAlgorithm      NcryptAlgorithm = "KEY_STORAGE"
	//
	// This algorithm is not supported by any BCrypt provider. This identifier is for creating
	// persistent stored HMAC keys in the TPM KSP.
	//
	NcryptHmacSha256Algorithm NcryptAlgorithm = "HMAC-SHA256"
)

//
// Interfaces
//

type NcryptInterface uint32

const (
	NcryptCipherInterface               NcryptInterface = 0x00000001
	NcryptHashInterface                 NcryptInterface = 0x00000002
	NcryptAsymmetricEncryptionInterface NcryptInterface = 0x00000003
	NcryptSecretAgreementInterface      NcryptInterface = 0x00000004
	NcryptSignatureInterface            NcryptInterface = 0x00000005
	NcryptKeyDerivationInterface        NcryptInterface = 0x00000007
	NcryptKeyStorageInterface           NcryptInterface = 0x00010001
	NcryptSchannelInterface             NcryptInterface = 0x00010002
	NcryptSchannelSignatureInterface    NcryptInterface = 0x00010003
	NcryptKeyProtectionInterface        NcryptInterface = 0x00010004
)

func (i *NcryptInterface) String() string {
	switch *i {
	case NcryptCipherInterface:
		return "Cipher"
	case NcryptHashInterface:
		return "Hash"
	case NcryptAsymmetricEncryptionInterface:
		return "AsymmetricEncryption"
	case NcryptSecretAgreementInterface:
		return "SecretAgreement"
	case NcryptSignatureInterface:
		return "Signature"
	case NcryptKeyDerivationInterface:
		return "KeyDerivation"
	case NcryptKeyStorageInterface:
		return "KeyStorage"
	case NcryptSchannelInterface:
		return "Schannel"
	case NcryptSchannelSignatureInterface:
		return "SchannelSignature"
	case NcryptKeyProtectionInterface:
		return "KeyProtection"
	default:
		return "N/A"
	}
}

//
// Algorithm groups
//

type NcryptAlgorithmGroup string

const (
	NcryptRsaAlgorithmGroup   NcryptAlgorithmGroup = "RSA"
	NcryptDhAlgorithmGroup    NcryptAlgorithmGroup = "DH"
	NcryptDsaAlgorithmGroup   NcryptAlgorithmGroup = "DSA"
	NcryptEcdsaAlgorithmGroup NcryptAlgorithmGroup = "ECDSA"
	NcryptEcdhAlgorithmGroup  NcryptAlgorithmGroup = "ECDH"
	NcryptAesAlgorithmGroup   NcryptAlgorithmGroup = "AES"
	NcryptRc2AlgorithmGroup   NcryptAlgorithmGroup = "RC2"
	NcryptDesAlgorithmGroup   NcryptAlgorithmGroup = "DES"
	NcryptKeyDerivationGroup  NcryptAlgorithmGroup = "KEY_DERIVATION"
)

type NcryptVersion uint32

const (
	NcryptBufferVersion                                    NcryptVersion = 0
	NcryptIsolatedKeyAttestedAttributesV0                  NcryptVersion = 0
	NcryptIsolatedKeyAttestedAttributesCurrentVersion      NcryptVersion = NcryptIsolatedKeyAttestedAttributesV0
	NcryptVsmKeyAttestationStatementV0                     NcryptVersion = 0
	NcryptVsmKeyAttestationStatementCurrentVersion         NcryptVersion = NcryptVsmKeyAttestationStatementV0
	NcryptVsmKeyAttestationClaimRestrictionsV0             NcryptVersion = 0
	NcryptVsmKeyAttestationClaimRestrictionsCurrentVersion NcryptVersion = NcryptVsmKeyAttestationClaimRestrictionsV0
	NcryptExportedIsolatedKeyHeaderV0                      NcryptVersion = 0
	NcryptExportedIsolatedKeyHeaderCurrentVersion          NcryptVersion = NcryptExportedIsolatedKeyHeaderV0
	NcryptTpmPlatformAttestationStatementV0                NcryptVersion = 0
	NcryptTpmPlatformAttestationStatementCurrentVersion    NcryptVersion = NcryptTpmPlatformAttestationStatementV0
	NcryptKeyAccessPolicyVersion                           NcryptVersion = 1
)

type NcryptMagic uint32

const (
	NcryptRsaPublicMagic                          NcryptMagic = 0x31415352 // RSA1
	NcryptRsaPrivateMagic                         NcryptMagic = 0x32415352 // RSA2
	NcryptRsaFullPrivateMagic                     NcryptMagic = 0x33415352 // RSA3
	NcryptEcdhPublicP256Magic                     NcryptMagic = 0x314B4345 // ECK1
	NcryptEcdhPrivateP256Magic                    NcryptMagic = 0x324B4345 // ECK2
	NcryptEcdhPublicP384Magic                     NcryptMagic = 0x334B4345 // ECK3
	NcryptEcdhPrivateP384Magic                    NcryptMagic = 0x344B4345 // ECK4
	NcryptEcdhPublicP521Magic                     NcryptMagic = 0x354B4345 // ECK5
	NcryptEcdhPrivateP521Magic                    NcryptMagic = 0x364B4345 // ECK6
	NcryptEcdhPublicGenericMagic                  NcryptMagic = 0x504B4345 // ECKP
	NcryptEcdhPrivateGenericMagic                 NcryptMagic = 0x564B4345 // ECKV
	NcryptEcdsaPublicP256Magic                    NcryptMagic = 0x31534345 // ECS1
	NcryptEcdsaPrivateP256Magic                   NcryptMagic = 0x32534345 // ECS2
	NcryptEcdsaPublicP384Magic                    NcryptMagic = 0x33534345 // ECS3
	NcryptEcdsaPrivateP384Magic                   NcryptMagic = 0x34534345 // ECS4
	NcryptEcdsaPublicP521Magic                    NcryptMagic = 0x35534345 // ECS5
	NcryptEcdsaPrivateP521Magic                   NcryptMagic = 0x36534345 // ECS6
	NcryptEcdsaPublicGenericMagic                 NcryptMagic = 0x50444345 // ECDP
	NcryptEcdsaPrivateGenericMagic                NcryptMagic = 0x56444345 // ECDV
	NcryptDhPublicMagic                           NcryptMagic = 0x42504844 // DHPB
	NcryptDhPrivateMagic                          NcryptMagic = 0x56504844 // DHPV
	NcryptDsaPublicMagic                          NcryptMagic = 0x42505344 // DSPB
	NcryptDsaPrivateMagic                         NcryptMagic = 0x56505344 // DSPV
	NcryptDsaPublicMagicV2                        NcryptMagic = 0x32425044 // DPB2
	NcryptDsaPrivateMagicV2                       NcryptMagic = 0x32565044 // DPV2
	NcryptDhParametersMagic                       NcryptMagic = 0x4d504844 // DHPM
	NcryptKeyDataBlobMagic                        NcryptMagic = 0x4d42444b // Key Data Blob Magic (KDBM)
	NcryptDsaParametersMagic                      NcryptMagic = 0x4d505344 // DSPM
	NcryptDsaParametersMagicV2                    NcryptMagic = 0x324d5044 // DPM2
	NcryptEccParametersMagic                      NcryptMagic = 0x50434345 // ECCP
	NcryptPlatformAttestMagic                     NcryptMagic = 0x44504150 // 'PAPD'
	NcryptKeyAttestMagic                          NcryptMagic = 0x4450414b // 'KAPD'
	NcryptCipherKeyBlobMagic                      NcryptMagic = 0x52485043 // 'CPHR'
	NcryptKdfKeyBlobMagic                         NcryptMagic = 0x3146444B // 'KDF1'
	NcryptProtectedKeyBlobMagic                   NcryptMagic = 0x4B545250 // 'PRTK'
	NcryptTpmLoadableKeyBlobMagic                 NcryptMagic = 0x4D54504B // 'MTPK'
	NcryptVsmIsolatedKeyMagic                     NcryptMagic = 0x494d5356 // 'VSMI'
	NcryptPcpTpmWebAuthnAttestationStatementMagic NcryptMagic = 0x4157414b // 'KAWA'
	NcryptTpmPlatformAttestationStatementMagic    NcryptMagic = 0x414c5054 // 'TPLA'
)

type NcryptKeyBlobType string

const (
	NcryptPublicKeyBlob  NcryptKeyBlobType = "PUBLICBLOB"
	NcryptPrivateKeyBlob NcryptKeyBlobType = "PRIVATEBLOB"

	// The BCRYPT_RSAPUBLIC_BLOB and BCRYPT_RSAPRIVATE_BLOB blob types are used
	// to transport plaintext RSA keys. These blob types will be supported by
	// all RSA primitive providers.
	// The BCRYPT_RSAPRIVATE_BLOB includes the following values:
	// Public Exponent
	// Modulus
	// Prime1
	// Prime2
	NcryptRsaPublicBlob  NcryptKeyBlobType = "RSAPUBLICBLOB"
	NcryptRsaPrivateBlob NcryptKeyBlobType = "RSAPRIVATEBLOB"
	// The BCRYPT_RSAFULLPRIVATE_BLOB blob type is used to transport
	// plaintext private RSA keys.  It includes the following values:
	// Public Exponent
	// Modulus
	// Prime1
	// Prime2
	// Private Exponent mod (Prime1 - 1)
	// Private Exponent mod (Prime2 - 1)
	// Inverse of Prime2 mod Prime1
	// PrivateExponent
	NcryptRsaFullPrivateBlob   NcryptKeyBlobType = "RSAFULLPRIVATEBLOB"
	NcryptLegacyRsaPublicBlob  NcryptKeyBlobType = "CAPIPUBLICBLOB"
	NcryptLegacyRsaPrivateBlob NcryptKeyBlobType = "CAPIPRIVATEBLOB"

	// The BCRYPT_ECCPUBLIC_BLOB and BCRYPT_ECCPRIVATE_BLOB blob types are used
	// to transport plaintext ECC keys. These blob types will be supported by
	// all ECC primitive providers.
	NcryptEccPublicBlob      NcryptKeyBlobType = "ECCPUBLICBLOB"
	NcryptEccPrivateBlob     NcryptKeyBlobType = "ECCPRIVATEBLOB"
	NcryptEccFullPublicBlob  NcryptKeyBlobType = "ECCFULLPUBLICBLOB"
	NcryptEccFullPrivateBlob NcryptKeyBlobType = "ECCFULLPRIVATEBLOB"

	NcryptSslEccPublicBlob NcryptKeyBlobType = "SSLECCPUBLICBLOB"

	// The BCRYPT_DH_PUBLIC_BLOB and BCRYPT_DH_PRIVATE_BLOB blob types are used
	// to transport plaintext DH keys. These blob types will be supported by
	// all DH primitive providers.
	NcryptDhPublicBlob        NcryptKeyBlobType = "DHPUBLICBLOB"
	NcryptDhPrivateBlob       NcryptKeyBlobType = "DHPRIVATEBLOB"
	NcryptLegacyDhPublicBlob  NcryptKeyBlobType = "CAPIDHPUBLICBLOB"
	NcryptLegacyDhPrivateBlob NcryptKeyBlobType = "CAPIDHPRIVATEBLOB"

	// The BCRYPT_DSA_PUBLIC_BLOB and BCRYPT_DSA_PRIVATE_BLOB blob types are used
	// to transport plaintext DSA keys. These blob types will be supported by
	// all DSA primitive providers.
	NcryptDsaPublicBlob          NcryptKeyBlobType = "DSAPUBLICBLOB"
	NcryptDsaPrivateBlob         NcryptKeyBlobType = "DSAPRIVATEBLOB"
	NcryptLegacyDsaPublicBlob    NcryptKeyBlobType = "CAPIDSAPUBLICBLOB"
	NcryptLegacyDsaPrivateBlob   NcryptKeyBlobType = "CAPIDSAPRIVATEBLOB"
	NcryptLegacyDsaV2PublicBlob  NcryptKeyBlobType = "V2CAPIDSAPUBLICBLOB"
	NcryptLegacyDsaV2PrivateBlob NcryptKeyBlobType = "V2CAPIDSAPRIVATEBLOB"

	NcryptCipherKeyBlob           NcryptKeyBlobType = "CipherKeyBlob"
	NcryptKdfKeyBlob              NcryptKeyBlobType = "KDFKeyBlob"
	NcryptProtectedKeyBlob        NcryptKeyBlobType = "ProtectedKeyBlob"
	NcryptTpmLoadableKeyBlob      NcryptKeyBlobType = "PcpTpmProtectedKeyBlob"
	NcryptPkcs7EnvelopeBlob       NcryptKeyBlobType = "PKCS7_ENVELOPE"
	NcryptPkcs8PrivateKeyBlob     NcryptKeyBlobType = "PKCS8_PRIVATEKEY"
	NcryptOpaquetransportBlob     NcryptKeyBlobType = "OpaqueTransport"
	NcryptIsolatedKeyEnvelopeBlob NcryptKeyBlobType = "ISOLATED_KEY_ENVELOPE"
)

//
// NCrypt generic memory descriptors
//

type NcryptBufferDescriptor uint32

const (
	NcryptBufferEmpty                      NcryptBufferDescriptor = 0
	NcryptBufferData                       NcryptBufferDescriptor = 1
	NcryptBufferProtectionDescriptorString NcryptBufferDescriptor = 3 // The buffer contains a null-terminated Unicode string that contains the Protection Descriptor.
	NcryptBufferProtectionFlags            NcryptBufferDescriptor = 4 // DWORD flags to be passed to NCryptCreateProtectionDescriptor function.
	NcryptBufferSslClientRandom            NcryptBufferDescriptor = 20
	NcryptBufferSslServerRandom            NcryptBufferDescriptor = 21
	NcryptBufferSslHighestVersion          NcryptBufferDescriptor = 22
	NcryptBufferSslClearKey                NcryptBufferDescriptor = 23
	NcryptBufferSslKeyArgData              NcryptBufferDescriptor = 24
	NcryptBufferSslSessionHash             NcryptBufferDescriptor = 25
	NcryptBufferPkcsOid                    NcryptBufferDescriptor = 40
	NcryptBufferPkcsAlgOid                 NcryptBufferDescriptor = 41
	NcryptBufferPkcsAlgParam               NcryptBufferDescriptor = 42
	NcryptBufferPkcsAlgId                  NcryptBufferDescriptor = 43
	NcryptBufferPkcsAttrs                  NcryptBufferDescriptor = 44
	NcryptBufferPkcsKeyName                NcryptBufferDescriptor = 45
	NcryptBufferPkcsSecret                 NcryptBufferDescriptor = 46
	NcryptBufferCertBlob                   NcryptBufferDescriptor = 47

	// For threshold key attestation
	NcryptBufferClaimIdbindingNonce                NcryptBufferDescriptor = 48
	NcryptBufferClaimKeyattestationNonce           NcryptBufferDescriptor = 49
	NcryptBufferKeyPropertyFlags                   NcryptBufferDescriptor = 50
	NcryptBufferAttestationstatementBlob           NcryptBufferDescriptor = 51
	NcryptBufferAttestationClaimType               NcryptBufferDescriptor = 52
	NcryptBufferAttestationClaimChallengeRequired  NcryptBufferDescriptor = 53
	NcryptBufferVsmKeyAttestationClaimRestrictions NcryptBufferDescriptor = 54

	// For generic ecc
	NcryptBufferEccCurveName  NcryptBufferDescriptor = 60
	NcryptBufferEccParameters NcryptBufferDescriptor = 61

	// For TPM seal
	NcryptBufferTpmSealPassword       NcryptBufferDescriptor = 70
	NcryptBufferTpmSealPolicyinfo     NcryptBufferDescriptor = 71
	NcryptBufferTpmSealTicket         NcryptBufferDescriptor = 72
	NcryptBufferTpmSealNoDaProtection NcryptBufferDescriptor = 73

	// For TPM platform attestation statements
	NcryptBufferTpmPlatformClaimPcrMask      NcryptBufferDescriptor = 80
	NcryptBufferTpmPlatformClaimNonce        NcryptBufferDescriptor = 81
	NcryptBufferTpmPlatformClaimStaticCreate NcryptBufferDescriptor = 82
)

//
// Flags used with NcryptCipherPaddingInfo
//

type NcryptCipherPaddingInfoFlag uint32

const (
	NcryptCipherNoPaddingFlag    NcryptCipherPaddingInfoFlag = 0x00000000
	NcryptCipherBlockPaddingFlag NcryptCipherPaddingInfoFlag = 0x00000001
	NcryptCipherOtherPaddingFlag NcryptCipherPaddingInfoFlag = 0x00000002
)

func (f *NcryptCipherPaddingInfoFlag) String() string {
	switch *f {
	case NcryptCipherNoPaddingFlag:
		return "CipherNoPadding"
	case NcryptCipherBlockPaddingFlag:
		return "CipherBlockPadding"
	case NcryptCipherOtherPaddingFlag:
		return "CipherOtherPadding"
	default:
		return "N/A"
	}
}

//
// Key attestation claim types
//

type NcryptClaimType uint32

const (
	NcryptClaimAuthorityOnly              NcryptClaimType = 0x00000001
	NcryptClaimSubjectOnly                NcryptClaimType = 0x00000002
	NcryptClaimWebAuthSubjectOnly         NcryptClaimType = 0x00000102
	NcryptClaimAuthorityAndSubject        NcryptClaimType = 0x00000003
	NcryptClaimVsmKeyAttestationStatement NcryptClaimType = 0x00000004
	NcryptClaimUnknown                    NcryptClaimType = 0x00001000
	NcryptClaimPlatform                   NcryptClaimType = 0x00010000
)

func (t *NcryptClaimType) String() string {
	output := ""

	if *t&NcryptClaimAuthorityOnly == NcryptClaimAuthorityOnly {
		output += "ClaimAuthorityOnly;"
	}
	if *t&NcryptClaimSubjectOnly == NcryptClaimSubjectOnly {
		output += "ClaimSubjectOnly;"
	}
	if *t&NcryptClaimWebAuthSubjectOnly == NcryptClaimWebAuthSubjectOnly {
		output += "ClaimWebAuthSubjectOnly;"
	}
	if *t&NcryptClaimAuthorityAndSubject == NcryptClaimAuthorityAndSubject {
		output += "ClaimAuthorityAndSubject;"
	}
	if *t&NcryptClaimVsmKeyAttestationStatement == NcryptClaimVsmKeyAttestationStatement {
		output += "ClaimVsmKeyAttestationStatement;"
	}
	if *t&NcryptClaimUnknown == NcryptClaimUnknown {
		output += "ClaimUnknown;"
	}
	if *t&NcryptClaimPlatform == NcryptClaimPlatform {
		output += "ClaimPlatform;"
	}

	return output
}

//
// NCrypt API Flags
//

type NcryptFlag uint32

const (
	NcryptNoPaddingFlag              NcryptFlag = 0x00000001 // NCryptEncrypt/Decrypt
	NcryptPadPkcs1Flag               NcryptFlag = 0x00000002 // NCryptEncrypt/Decrypt NCryptSignHash/VerifySignature
	NcryptPadOaepFlag                NcryptFlag = 0x00000004 // BCryptEncrypt/Decrypt
	NcryptPadPssFlag                 NcryptFlag = 0x00000008 // BCryptSignHash/VerifySignature
	NcryptPadCipherFlag              NcryptFlag = 0x00000010 // NCryptEncrypt/Decrypt
	NcryptAttestationFlag            NcryptFlag = 0x00000020 // NCryptDecrypt for key attestation
	NcryptSealingFlag                NcryptFlag = 0x00000100 // NCryptEncrypt/Decrypt for sealing
	NcryptRegisterNotifyFlag         NcryptFlag = 0x00000001 // NCryptNotifyChangeKey
	NcryptUnregisterNotifyFlag       NcryptFlag = 0x00000002 // NCryptNotifyChangeKey
	NcryptNoKeyValidation            NcryptFlag = 0x00000008
	NcryptMachineKeyFlag             NcryptFlag = 0x00000020 // same as CAPI CRYPT_MACHINE_KEYSET
	NcryptSilentFlag                 NcryptFlag = 0x00000040 // same as CAPI CRYPT_SILENT
	NcryptOverwriteKeyFlag           NcryptFlag = 0x00000080
	NcryptWriteKeyToLegacyStoreFlag  NcryptFlag = 0x00000200
	NcryptDoNotFinalizeFlag          NcryptFlag = 0x00000400
	NcryptExportLegacyFlag           NcryptFlag = 0x00000800
	NcryptIgnoreDeviceStateFlag      NcryptFlag = 0x00001000 // NCryptOpenStorageProvider
	NcryptTreatNistAsGenericEccFlag  NcryptFlag = 0x00002000
	NcryptNoCachedPassword           NcryptFlag = 0x00004000
	NcryptProtectToLocalSystem       NcryptFlag = 0x00008000
	NcryptPersistOnlyFlag            NcryptFlag = 0x40000000
	NcryptPersistFlag                NcryptFlag = 0x80000000
	NcryptPreferVirtualIsolationFlag NcryptFlag = 0x00010000 // NCryptCreatePersistedKey NCryptImportKey
	NcryptUseVirtualIsolationFlag    NcryptFlag = 0x00020000 // NCryptCreatePersistedKey NCryptImportKey
	NcryptUsePerBootKeyFlag          NcryptFlag = 0x00040000 // NCryptCreatePersistedKey NCryptImportKey

	// TPM NCryptSignHash Flag
	NcryptTpmPadPssIgnoreSalt NcryptFlag = 0x00000020 // NCryptSignHash
)

//
// AlgOperations flags for use with NCryptEnumAlgorithms()
//

type NcryptAlgOperation uint32

const (
	NcryptCipherOperation               NcryptAlgOperation = 0x00000001
	NcryptHashOperation                 NcryptAlgOperation = 0x00000002
	NcryptAsymmetricEncryptionOperation NcryptAlgOperation = 0x00000004
	NcryptSecretAgreementOperation      NcryptAlgOperation = 0x00000008
	NcryptSignatureOperation            NcryptAlgOperation = 0x00000010
	NcryptRngOperation                  NcryptAlgOperation = 0x00000020
	NcryptKeyDerivationOperation        NcryptAlgOperation = 0x00000040
)

func (o *NcryptAlgOperation) String() string {
	output := ""

	if *o&NcryptCipherOperation == NcryptCipherOperation {
		output += "Cipher;"
	}
	if *o&NcryptHashOperation == NcryptHashOperation {
		output += "Hash;"
	}
	if *o&NcryptAsymmetricEncryptionOperation == NcryptAsymmetricEncryptionOperation {
		output += "AsymmetricEncryption;"
	}
	if *o&NcryptSecretAgreementOperation == NcryptSecretAgreementOperation {
		output += "SecretAgreement;"
	}
	if *o&NcryptSignatureOperation == NcryptSignatureOperation {
		output += "Signature;"
	}
	if *o&NcryptRngOperation == NcryptRngOperation {
		output += "Rng;"
	}
	if *o&NcryptKeyDerivationOperation == NcryptKeyDerivationOperation {
		output += "KeyDerivation;"
	}

	return output
}

type NcryptProperty string

const (
	//
	// Standard property names.
	//

	NcryptNameProperty                 NcryptProperty = "Name"
	NcryptUniqueNameProperty           NcryptProperty = "Unique Name"
	NcryptAlgorithmProperty            NcryptProperty = "Algorithm Name"
	NcryptLengthProperty               NcryptProperty = "Length"
	NcryptLengthsProperty              NcryptProperty = "Lengths"
	NcryptBlockLengthProperty          NcryptProperty = "Block Length"
	NcryptPublicLengthProperty         NcryptProperty = "PublicKeyLength"
	NcryptSignatureLengthProperty      NcryptProperty = "SignatureLength"
	NcryptChainingModeProperty         NcryptProperty = "Chaining Mode"
	NcryptAuthTagLength                NcryptProperty = "AuthTagLength"
	NcryptUiPolicyProperty             NcryptProperty = "UI Policy"
	NcryptExportPolicyProperty         NcryptProperty = "Export Policy"
	NcryptWindowHandleProperty         NcryptProperty = "HWND Handle"
	NcryptUseContextProperty           NcryptProperty = "Use Context"
	NcryptImplTypeProperty             NcryptProperty = "Impl Type"
	NcryptKeyUsageProperty             NcryptProperty = "Key Usage"
	NcryptKeyTypeProperty              NcryptProperty = "Key Type"
	NcryptVersionProperty              NcryptProperty = "Version"
	NcryptSecurityDescrSupportProperty NcryptProperty = "Security Descr Support"
	NcryptSecurityDescrProperty        NcryptProperty = "Security Descr"
	NcryptUseCountEnabledProperty      NcryptProperty = "Enabled Use Count"
	NcryptUseCountProperty             NcryptProperty = "Use Count"
	NcryptLastModifiedProperty         NcryptProperty = "Modified"
	NcryptMaxNameLengthProperty        NcryptProperty = "Max Name Length"
	NcryptAlgorithmGroupProperty       NcryptProperty = "Algorithm Group"
	NcryptDhParametersProperty         NcryptProperty = "DHParameters"
	NcryptEccParametersProperty        NcryptProperty = "ECCParameters"
	NcryptEccCurveNameProperty         NcryptProperty = "ECCCurveName"
	NcryptEccCurveNameListProperty     NcryptProperty = "ECCCurveNameList"
	NcryptUseVirtualIsolationProperty  NcryptProperty = "Virtual Iso"
	NcryptUsePerBootKeyProperty        NcryptProperty = "Per Boot Key"
	NcryptProviderHandleProperty       NcryptProperty = "Provider Handle"
	NcryptPinProperty                  NcryptProperty = "SmartCardPin"
	NcryptReaderProperty               NcryptProperty = "SmartCardReader"
	NcryptSmartcardGuidProperty        NcryptProperty = "SmartCardGuid"
	NcryptCertificateProperty          NcryptProperty = "SmartCardKeyCertificate"
	NcryptPinPromptProperty            NcryptProperty = "SmartCardPinPrompt"
	NcryptUserCertstoreProperty        NcryptProperty = "SmartCardUserCertStore"
	NcryptRootCertstoreProperty        NcryptProperty = "SmartcardRootCertStore"
	NcryptSecurePinProperty            NcryptProperty = "SmartCardSecurePin"
	NcryptAssociatedEcdhKey            NcryptProperty = "SmartCardAssociatedECDHKey"
	NcryptScardPinId                   NcryptProperty = "SmartCardPinId"
	NcryptScardPinInfo                 NcryptProperty = "SmartCardPinInfo"
	NcryptReaderIconProperty           NcryptProperty = "SmartCardReaderIcon"
	NcryptKdfSecretValue               NcryptProperty = "KDFKeySecret"
	NcryptDismissUiTimeoutSecProperty  NcryptProperty = "SmartCardDismissUITimeoutSeconds"

	//
	// Additional property strings specific for the Platform Crypto Provider
	//

	NcryptPcpPlatformTypeProperty                 NcryptProperty = "PCP_PLATFORM_TYPE"
	NcryptPcpProviderVersionProperty              NcryptProperty = "PCP_PROVIDER_VERSION"
	NcryptPcpEkpubProperty                        NcryptProperty = "PCP_EKPUB"
	NcryptPcpEkcertProperty                       NcryptProperty = "PCP_EKCERT"
	NcryptPcpEknvcertProperty                     NcryptProperty = "PCP_EKNVCERT"
	NcryptPcpRsaEkpubProperty                     NcryptProperty = "PCP_RSA_EKPUB"
	NcryptPcpRsaEkcertProperty                    NcryptProperty = "PCP_RSA_EKCERT"
	NcryptPcpRsaEknvcertProperty                  NcryptProperty = "PCP_RSA_EKNVCERT"
	NcryptPcpEccEkpubProperty                     NcryptProperty = "PCP_ECC_EKPUB"
	NcryptPcpEccEkcertProperty                    NcryptProperty = "PCP_ECC_EKCERT"
	NcryptPcpEccEknvcertProperty                  NcryptProperty = "PCP_ECC_EKNVCERT"
	NcryptPcpSrkpubProperty                       NcryptProperty = "PCP_SRKPUB"
	NcryptPcpPcrtableProperty                     NcryptProperty = "PCP_PCRTABLE"
	NcryptPcpChangepasswordProperty               NcryptProperty = "PCP_CHANGEPASSWORD"
	NcryptPcpPasswordRequiredProperty             NcryptProperty = "PCP_PASSWORD_REQUIRED"
	NcryptPcpUsageauthProperty                    NcryptProperty = "PCP_USAGEAUTH"
	NcryptPcpMigrationpasswordProperty            NcryptProperty = "PCP_MIGRATIONPASSWORD"
	NcryptPcpExportAllowedProperty                NcryptProperty = "PCP_EXPORT_ALLOWED"
	NcryptPcpStorageparentProperty                NcryptProperty = "PCP_STORAGEPARENT"
	NcryptPcpProviderhandleProperty               NcryptProperty = "PCP_PROVIDERMHANDLE"
	NcryptPcpPlatformhandleProperty               NcryptProperty = "PCP_PLATFORMHANDLE"
	NcryptPcpPlatformBindingPcrmaskProperty       NcryptProperty = "PCP_PLATFORM_BINDING_PCRMASK"
	NcryptPcpPlatformBindingPcrdigestlistProperty NcryptProperty = "PCP_PLATFORM_BINDING_PCRDIGESTLIST"
	NcryptPcpPlatformBindingPcrdigestProperty     NcryptProperty = "PCP_PLATFORM_BINDING_PCRDIGEST"
	NcryptPcpKeyUsagePolicyProperty               NcryptProperty = "PCP_KEY_USAGE_POLICY"
	NcryptPcpRsaSchemeProperty                    NcryptProperty = "PCP_RSA_SCHEME"
	NcryptPcpRsaSchemeHashAlgProperty             NcryptProperty = "PCP_RSA_SCHEME_HASH_ALG"
	NcryptPcpTpm12IdbindingProperty               NcryptProperty = "PCP_TPM12_IDBINDING"
	NcryptPcpTpm12IdbindingDynamicProperty        NcryptProperty = "PCP_TPM12_IDBINDING_DYNAMIC"
	NcryptPcpTpm12IdactivationProperty            NcryptProperty = "PCP_TPM12_IDACTIVATION"
	NcryptPcpKeyattestationProperty               NcryptProperty = "PCP_TPM12_KEYATTESTATION"
	NcryptPcpAlternateKeyStorageLocationProperty  NcryptProperty = "PCP_ALTERNATE_KEY_STORAGE_LOCATION"
	NcryptPcpTpmIfxRsaKeygenProhibitedProperty    NcryptProperty = "PCP_TPM_IFX_RSA_KEYGEN_PROHIBITED"
	NcryptPcpTpmIfxRsaKeygenVulnerabilityProperty NcryptProperty = "PCP_TPM_IFX_RSA_KEYGEN_VULNERABILITY"
	NcryptPcpHmacAuthPolicyref                    NcryptProperty = "PCP_HMAC_AUTH_POLICYREF"
	NcryptPcpHmacAuthPolicyinfo                   NcryptProperty = "PCP_HMAC_AUTH_POLICYINFO"
	NcryptPcpHmacAuthNonce                        NcryptProperty = "PCP_HMAC_AUTH_NONCE"
	NcryptPcpHmacAuthSignature                    NcryptProperty = "PCP_HMAC_AUTH_SIGNATURE"
	NcryptPcpHmacAuthTicket                       NcryptProperty = "PCP_HMAC_AUTH_TICKET"
	NcryptPcpNoDaProtectionProperty               NcryptProperty = "PCP_NO_DA_PROTECTION"
	NcryptPcpTpmManufacturerIdProperty            NcryptProperty = "PCP_TPM_MANUFACTURER_ID"
	NcryptPcpTpmFwVersionProperty                 NcryptProperty = "PCP_TPM_FW_VERSION"
	NcryptPcpTpm2bnameProperty                    NcryptProperty = "PCP_TPM2BNAME"
	NcryptPcpTpmVersionProperty                   NcryptProperty = "PCP_TPM_VERSION"
	NcryptPcpRawPolicydigestProperty              NcryptProperty = "PCP_RAW_POLICYDIGEST"
	NcryptPcpKeyCreationhashProperty              NcryptProperty = "PCP_KEY_CREATIONHASH"
	NcryptPcpKeyCreationticketProperty            NcryptProperty = "PCP_KEY_CREATIONTICKET"
	NcryptPcpSessionidProperty                    NcryptProperty = "PCP_SESSIONID"
	NcryptPcpPssSaltSizeProperty                  NcryptProperty = "PSS Salt Size"

	//
	// Additional property strings specific for the Smart Card Key Storage Provider
	//

	NcryptScardNgcKeyName                    NcryptProperty = "SmartCardNgcKeyName"
	NcryptPcpPlatformBindingPcralgidProperty NcryptProperty = "PCP_PLATFORM_BINDING_PCRALGID"

	//
	// Used to set IV for block ciphers, before calling NCryptEncrypt/NCryptDecrypt
	//

	NcryptInitializationVector NcryptProperty = "IV"

	NcryptChangepasswordProperty              NcryptProperty = NcryptPcpChangepasswordProperty
	NcryptAlternateKeyStorageLocationProperty NcryptProperty = NcryptPcpAlternateKeyStorageLocationProperty
	NcryptKeyAccessPolicyProperty             NcryptProperty = "Key Access Policy"

	//
	// Pin Cache Provider Properties
	//

	NcryptPinCacheFreeApplicationTicketProperty NcryptProperty = "PinCacheFreeApplicationTicket"
	NcryptPinCacheFlagsProperty                 NcryptProperty = "PinCacheFlags"
)

//
// PCP_KEY_USAGE_POLICY (NcryptPcpKeyUsagePolicyProperty) values
//

type NcryptPcpKeyUsagePolicyPropertyFlag uint32

const (
	NcryptTpm12Provider          NcryptPcpKeyUsagePolicyPropertyFlag = 0x00010000
	NcryptPcpSignatureKey        NcryptPcpKeyUsagePolicyPropertyFlag = 0x00000001
	NcryptPcpEncryptionKey       NcryptPcpKeyUsagePolicyPropertyFlag = 0x00000002
	NcryptPcpGenericKey          NcryptPcpKeyUsagePolicyPropertyFlag = NcryptPcpSignatureKey | NcryptPcpEncryptionKey
	NcryptPcpStorageKey          NcryptPcpKeyUsagePolicyPropertyFlag = 0x00000004
	NcryptPcpIdentityKey         NcryptPcpKeyUsagePolicyPropertyFlag = 0x00000008
	NcryptPcpHmacverificationKey NcryptPcpKeyUsagePolicyPropertyFlag = 0x00000010
)

func (p *NcryptPcpKeyUsagePolicyPropertyFlag) String() string {
	output := ""

	if *p&NcryptTpm12Provider == NcryptTpm12Provider {
		output += "Tpm12;"
	}
	if *p&NcryptPcpSignatureKey == NcryptPcpSignatureKey {
		output += "Signature;"
	}
	if *p&NcryptPcpEncryptionKey == NcryptPcpEncryptionKey {
		output += "Encryption;"
	}
	if *p&NcryptPcpStorageKey == NcryptPcpStorageKey {
		output += "Storage;"
	}
	if *p&NcryptPcpIdentityKey == NcryptPcpIdentityKey {
		output += "Identity;"
	}
	if *p&NcryptPcpHmacverificationKey == NcryptPcpHmacverificationKey {
		output += "Hmacverification;"
	}

	return output
}

//
// PCP_TPM_IFX_RSA_KEYGEN_VULNERABILITY (NcryptPcpTpmIfxRsaKeygenVulnerabilityProperty) values
//

type NcryptPcpTpmIfxRsaKeygenVulnerabilityPropertyFlags uint32

const (
	IfxRsaKeygenVulNotAffected    NcryptPcpTpmIfxRsaKeygenVulnerabilityPropertyFlags = 0
	IfxRsaKeygenVulAffectedLevel1 NcryptPcpTpmIfxRsaKeygenVulnerabilityPropertyFlags = 1
	IfxRsaKeygenVulAffectedLevel2 NcryptPcpTpmIfxRsaKeygenVulnerabilityPropertyFlags = 2
)

//
// NCRYPT_EXPORT_POLICY_PROPERTY property (NcryptExportPolicyProperty) flags
//

type NcryptExportPolicyPropertyFlag uint32

const (
	NcryptAllowExportFlag             NcryptExportPolicyPropertyFlag = 0x00000001
	NcryptAllowPlaintextExportFlag    NcryptExportPolicyPropertyFlag = 0x00000002
	NcryptAllowArchivingFlag          NcryptExportPolicyPropertyFlag = 0x00000004
	NcryptAllowPlaintextArchivingFlag NcryptExportPolicyPropertyFlag = 0x00000008
)

func (p *NcryptExportPolicyPropertyFlag) String() string {
	output := ""

	if *p&NcryptAllowExportFlag == NcryptAllowExportFlag {
		output += "AllowExport;"
	}
	if *p&NcryptAllowPlaintextExportFlag == NcryptAllowPlaintextExportFlag {
		output += "AllowPlaintextExport;"
	}
	if *p&NcryptAllowArchivingFlag == NcryptAllowArchivingFlag {
		output += "AllowArchiving;"
	}
	if *p&NcryptAllowPlaintextArchivingFlag == NcryptAllowPlaintextArchivingFlag {
		output += "AllowPlaintextArchiving;"
	}

	return output
}

//
// NCRYPT_IMPL_TYPE_PROPERTY property (NcryptImplTypeProperty) flags
//

type NcryptImplTypePropertyFlag uint32

const (
	NcryptImplHardwareFlag         NcryptImplTypePropertyFlag = 0x00000001
	NcryptImplSoftwareFlag         NcryptImplTypePropertyFlag = 0x00000002
	NcryptImplRemovableFlag        NcryptImplTypePropertyFlag = 0x00000008
	NcryptImplHardwareRngFlag      NcryptImplTypePropertyFlag = 0x00000010
	NcryptImplVirtualIsolationFlag NcryptImplTypePropertyFlag = 0x00000020
)

func (p *NcryptImplTypePropertyFlag) String() string {
	output := ""

	if *p&NcryptImplHardwareFlag == NcryptImplHardwareFlag {
		output += "Hardware;"
	}
	if *p&NcryptImplSoftwareFlag == NcryptImplSoftwareFlag {
		output += "Software;"
	}
	if *p&NcryptImplRemovableFlag == NcryptImplRemovableFlag {
		output += "Removable;"
	}
	if *p&NcryptImplHardwareRngFlag == NcryptImplHardwareRngFlag {
		output += "lHardwareRng;"
	}
	if *p&NcryptImplVirtualIsolationFlag == NcryptImplVirtualIsolationFlag {
		output += "VirtualIsolation;"
	}

	return output
}

//
// NCRYPT_KEY_USAGE_PROPERTY property (NcryptKeyUsageProperty) flags.
//

type NcryptKeyUsagePropertyFlag uint32

const (
	NcryptAllowDecryptFlag      NcryptKeyUsagePropertyFlag = 0x00000001
	NcryptAllowSigningFlag      NcryptKeyUsagePropertyFlag = 0x00000002
	NcryptAllowKeyAgreementFlag NcryptKeyUsagePropertyFlag = 0x00000004
	NcryptAllowKeyImportFlag    NcryptKeyUsagePropertyFlag = 0x00000008
	NcryptAllowAllUsages        NcryptKeyUsagePropertyFlag = 0x00ffffff
)

func (p *NcryptKeyUsagePropertyFlag) String() string {
	output := ""

	if *p&NcryptAllowDecryptFlag == NcryptAllowDecryptFlag {
		output += "Decrypt;"
	}
	if *p&NcryptAllowSigningFlag == NcryptAllowSigningFlag {
		output += "Signing;"
	}
	if *p&NcryptAllowKeyAgreementFlag == NcryptAllowKeyAgreementFlag {
		output += "KeyAgreement;"
	}
	if *p&NcryptAllowKeyImportFlag == NcryptAllowKeyImportFlag {
		output += "Import;"
	}
	if *p&NcryptAllowAllUsages == NcryptAllowAllUsages {
		output += "All;"
	}

	return output
}

//
// NCRYPT_UI_POLICY_PROPERTY property (NcryptUiPolicyProperty) flags and structure
//

type NcryptUiPolicyPropertyFlag uint32

const (
	NcryptUiProtectKeyFlag               NcryptUiPolicyPropertyFlag = 0x00000001
	NcryptUiForceHighProtectionFlag      NcryptUiPolicyPropertyFlag = 0x00000002
	NcryptUiFingerprintProtectionFlag    NcryptUiPolicyPropertyFlag = 0x00000004
	NcryptUiAppcontainerAccessMediumFlag NcryptUiPolicyPropertyFlag = 0x00000008
)

func (p *NcryptUiPolicyPropertyFlag) String() string {
	output := ""

	if *p&NcryptUiProtectKeyFlag == NcryptUiProtectKeyFlag {
		output += "ProtectKey;"
	}
	if *p&NcryptUiForceHighProtectionFlag == NcryptUiForceHighProtectionFlag {
		output += "ForceHighProtection;"
	}
	if *p&NcryptUiFingerprintProtectionFlag == NcryptUiFingerprintProtectionFlag {
		output += "FingerprintProtection;"
	}
	if *p&NcryptUiAppcontainerAccessMediumFlag == NcryptUiAppcontainerAccessMediumFlag {
		output += "AppcontainerAccessMedium;"
	}

	return output
}

//
// The NCRYPT_PIN_CACHE_FLAGS_PROPERTY property (NcryptPinCacheFlagsProperty)
// is a DWORD value that can be set from a trusted process.
// The following flags can be set:
//

type NcryptPinCacheFlagsPropertyFlag uint32

const (
	NcryptPinCacheDisableDplFlag = 0x00000001
)

//
// The NCRYPT_PIN_CACHE_CLEAR_PROPERTY property (NcryptPinCacheClearProperty)
// is a DWORD value.
// The following option can be set:
//

type NcryptPinCacheClearPropertyFlag uint32

const (
	NcryptPinCacheClearForCallingProcessOption NcryptPinCacheClearPropertyFlag = 0x00000001
)

type NcryptIsolatedKeyFlag uint32

const (
	NcryptIsolatedKeyFlagCreatedInIsolation NcryptIsolatedKeyFlag = 0x00000001 // if set, this key was generated in isolation, not imported
	NcryptIsolatedKeyFlagImportOnly         NcryptIsolatedKeyFlag = 0x00000002 // if set, this key can only be used for importing other keys
)

const (
	//
	// TPM RSAPSS Salt size types
	// PSS Salt Size (NcryptPcpPssSaltSizeProperty) values
	//

	NcryptTpmPssSaltSizeUnknown  = 0x00000000
	NcryptTpmPssSaltSizeMaximum  = 0x00000001 // Pre-TPM Spec-1.16: Max allowed salt size
	NcryptTpmPssSaltSizeHashsize = 0x00000002 // Post-1.16: PSS salt = hashLen

	// Maximum length of property name (in characters)
	NcryptMaxPropertyName = 64

	// Maximum length of property data (in bytes)
	NcryptMaxPropertyData = 0x100000

	//
	// Pin Cache Key Properties
	//

	NcryptPinCacheApplicationTicketProperty = "PinCacheApplicationTicket"
	NcryptPinCacheApplicationImageProperty  = "PinCacheApplicationImage"
	NcryptPinCacheApplicationStatusProperty = "PinCacheApplicationStatus"
	NcryptPinCachePinProperty               = "PinCachePin"
	NcryptPinCacheIsGestureRequiredProperty = "PinCacheIsGestureRequired"
	NcryptPinCacheRequireGestureFlag        = 0x00000001

	//
	// The NCRYPT_PIN_CACHE_PIN_PROPERTY and NCRYPT_PIN_CACHE_APPLICATION_TICKET_PROPERTY properties
	// return a 32 byte random unique ID encoded as a null terminated base64 Unicode string. The string length
	// is 32 * 4/3 + 1 characters = 45 characters, 90 bytes
	//

	NcryptPinCachePinByteLength               = 90
	NcryptPinCacheApplicationTicketByteLength = 90
	NcryptPinCacheClearProperty               = "PinCacheClear"

	NcryptAllowSilentKeyAccess = 0x00000001
)

// NCRYPT shares the same BCRYPT definitions
type NcryptBuffer BcryptBuffer
type NcryptBufferDesc BcryptBufferDesc

//
// NCrypt handles
//

type NcryptHandle uintptr
type NcryptProvHandle NcryptHandle
type NcryptKeyHandle NcryptHandle
type NcryptHashHandle NcryptHandle
type NcryptSecretHandle NcryptHandle

const invalidHandleValue = ^NcryptHandle(0)

//
// NCrypt structures.
//

// NCRYPT_CIPHER_PADDING_INFO
type NcryptCipherPaddingInfo struct {
	// size of this struct
	Size uint32

	// See NCRYPT_CIPHER_ flag values
	Flags NcryptCipherPaddingInfoFlag

	// [in, out, optional]
	// The address of a buffer that contains the initialization vector (IV) to use during encryption.
	// The cbIV parameter contains the size of this buffer. This function will modify the contents of this buffer.
	// If you need to reuse the IV later, make sure you make a copy of this buffer before calling this function.
	IV    *byte
	IVLen uint32

	// [in, out, optional]
	// The address of a buffer that contains the algorithm specific info to use during encryption.
	// The cbOtherInfo parameter contains the size of this buffer. This function will modify the contents of this buffer.
	// If you need to reuse the buffer later, make sure you make a copy of this buffer before calling this function.
	//
	// For Microsoft providers, when an authenticated encryption mode is used,
	// this parameter must point to a serialized BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO structure.
	//
	// NOTE: All pointers inside a structure must be to a data allocated within pbOtherInfo buffer.
	//
	OtherInfo    *byte
	OtherInfoLen uint32
}

// NCRYPT_PLATFORM_ATTEST_PADDING_INFO
type NcryptPlatformAttestPaddingInfo struct {
	Magic   NcryptMagic // 'PAPD'
	PcrMask uint32
}

// NCRYPT_KEY_ATTEST_PADDING_INFO
type NcryptKeyAttestPaddingInfo struct {
	Magic      NcryptMagic // 'KAPD'
	KeyBlob    *byte
	KeyBlobLen uint32
	KeyAuth    *byte
	KeyAuthLen uint32
}

//
// Buffer contents for NCryptCreateClaim
//

// NCRYPT_ISOLATED_KEY_ATTESTED_ATTRIBUTES
type NcryptIsolatedKeyAttestedAttributes struct {
	Version          NcryptVersion         // set to NCRYPT_ISOLATED_KEY_ATTESTED_ATTRIBUTES_V0
	Flags            NcryptIsolatedKeyFlag // NCRYPT_ISOLATED_KEY_FLAG_ flags
	PublicKeyBlobLen uint32
	// pbPublicKeyBlob[cbPublicKeyBlob] - exported public key
}

// NCRYPT_VSM_KEY_ATTESTATION_STATEMENT
type NcryptVsmKeyAttestationStatement struct {
	Magic         NcryptMagic   // {'I', 'M', 'S', 'V'} - 'VSMI' for VSM Isolated
	Version       NcryptVersion // Set to NCRYPT_VSM_KEY_ATTESTATION_STATEMENT_CURRENT_VERSION
	SignatureLen  uint32        // Secure kernel signature over the isolation report
	ReportLen     uint32        // Key isolation report from the secure kernel
	AttributesLen uint32        // Attributes of the isolated key including public key blob
	// UCHAR Signature[cbSignature]    -- Secure kernel signature of the report
	// UCHAR Report[cbReport]          -- Secure kernel report including hash of Attributes
	// UCHAR Attributes[cbAttributes]  -- Trustlet-reported attributes of the key
}

//
// Buffer contents for NCryptVerifyClaim (for buffer type NCRYPTBUFFER_ISOLATED_KEY_ATTESTATION_CLAIM_RESTRICTIONS)
//

// NCRYPT_VSM_KEY_ATTESTATION_CLAIM_RESTRICTIONS
type NcryptVsmKeyAttestationClaimRestrictions struct {
	Version       NcryptVersion // Set to NCRYPT_VSM_KEY_ATTESTATION_CLAIM_RESTRICTIONS_V0
	TrustletId    uint64        // Trustlet type
	MinSvn        uint32        // Minimum acceptable trustlet SVN, 0 if don't care
	FlagsMask     uint32        // Which of NCRYPT_ISOLATED_KEY_ flags to check
	FlagsExpected uint32        // Expected values of flags inside the mask
	reserved      uint32        // Keep the AllowDebugging flag and Reserved bits in the same uint32
}

func (r *NcryptVsmKeyAttestationClaimRestrictions) SetAllowDebugging(value bool) {
	if value {
		r.reserved |= 1 // Set the least significant bit
	} else {
		r.reserved &= ^uint32(1) // Clear the least significant bit
	}
}
func (r *NcryptVsmKeyAttestationClaimRestrictions) SetReserved(value uint32) {
	r.reserved = (r.reserved & 1) | ((value & ((1 << 31) - 1)) << 1) // Preserve the least significant bit and update the reserved bits
}
func (r *NcryptVsmKeyAttestationClaimRestrictions) GetAllowDebugging() bool {
	return (r.reserved & 1) != 0 // Check if the least significant bit is set
}
func (r *NcryptVsmKeyAttestationClaimRestrictions) GetReserved() uint32 {
	return (r.reserved >> 1) & ((1 << 31) - 1) // Get the reserved bits by shifting right and applying a mask
}

//
// Structures to assist with importation of isolated keys
//

type NcryptExportedIsolatedKeyHeader struct {
	Version        NcryptVersion
	KeyUsage       NcryptKeyUsagePropertyFlag
	Reserved       uint32 // Keep the PerBootKey flag and Reserved bits in the same uint32
	AlgNameLen     uint32
	NonceLen       uint32
	AuthTagLen     uint32
	WrappingKeyLen uint32
	IsolatedKeyLen uint32
}

func (h *NcryptExportedIsolatedKeyHeader) SetPerBootKey(value bool) {
	if value {
		h.Reserved |= 1 // Set the least significant bit
	} else {
		h.Reserved &= ^uint32(1) // Clear the least significant bit
	}
}
func (h *NcryptExportedIsolatedKeyHeader) SetReserved(value uint32) {
	h.Reserved = (h.Reserved & 1) | ((value & ((1 << 31) - 1)) << 1) // Preserve the least significant bit and update the reserved bits
}
func (h *NcryptExportedIsolatedKeyHeader) GetPerBootKey() bool {
	return (h.Reserved & 1) != 0 // Check if the least significant bit is set
}
func (h *NcryptExportedIsolatedKeyHeader) GetReserved() uint32 {
	return (h.Reserved >> 1) & ((1 << 31) - 1) // Get the reserved bits by shifting right and applying a mask
}

type NcryptExportedIsolatedKeyEnvelope struct {
	Header NcryptExportedIsolatedKeyHeader
	// UCHAR AlgorithmName[Header.cbAlgName]       -- Unicode algorithm name including terminating NULL
	// UCHAR Nonce[Header.cbNonce]                 -- Nonce buffer used when encrypting isolated key
	// ---- data after this point is not integrity protected in transit
	// UCHAR AesGcmAuthTag[Header.cbAuthTag]
	// UCHAR WrappingKeyBlob[Header.cbWrappingKey] -- RSA-OAEP encrypted AES wrapping key
	// UCHAR IsolatedKeyBlob[Header.cbIsolatedKey] -- AES-GCM encrypted key to import
}

type NcryptPcpTpmWebAuthnAttestationStatement struct {
	Magic          NcryptMagic // { 'A', 'W', 'A', 'K' } - 'KAWA'
	Version        uint32      // 1 for the statement defined in this specification
	HeaderSize     uint32      // 24
	CertifyInfoLen uint32
	SignatureLen   uint32
	TpmPublicLen   uint32
	// CertifyInfo[cbCertifyInfo];
	// Signature[cbSignature];
	// TpmPublic[cbTpmPublic];
}

type NcryptTpmPlatformAttestationStatement struct {
	Magic        NcryptMagic   // {'A', 'L', 'P', 'T'} - 'TPLA' for TPM Platform
	Version      NcryptVersion // Set to NCRYPT_TPM_PLATFORM_ATTESTATION_STATEMENT_CURRENT_VERSION
	PcrAlg       uint32        // The TPM hash algorithm ID
	SignatureLen uint32        // TPMT_SIGNATURE structure signature over the quote
	QuoteLen     uint32        // TPMS_ATTEST structure that was generated and signed
	PcrsLen      uint32        // Raw concatenation of all 24 PCRs
	// UCHAR Signature[cbSignature]
	// UCHAR Quote[cbQuote]
	// UCHAR Pcrs[cbPcrs]
}

// This is the actual golang equivalent of Windows NCryptAlgorithmName.
type ncryptAlgorithmName struct {
	Name          *uint16
	Class         NcryptInterface    // the CNG interface that supports this algorithm
	AlgOperations NcryptAlgOperation // the types of operations supported by this algorithm
	Flags         uint32
}

type NcryptAlgorithmInfo struct {
	Name          string
	Class         NcryptInterface    // the CNG interface that supports this algorithm
	AlgOperations NcryptAlgOperation // the types of operations supported by this algorithm
	Flags         uint32
}

func (n *NcryptAlgorithmInfo) fromInternal(internalNcryptAlgorithmName ncryptAlgorithmName) {
	n.Name = utf16PtrToString(internalNcryptAlgorithmName.Name)
	n.Class = internalNcryptAlgorithmName.Class
	n.AlgOperations = internalNcryptAlgorithmName.AlgOperations
	n.Flags = internalNcryptAlgorithmName.Flags
}
func (n *NcryptAlgorithmInfo) toInternal() (ncryptAlgorithmName, error) {
	nameUtf16Ptr, err := stringToUtf16Ptr(n.Name)
	if err != nil {
		return ncryptAlgorithmName{}, fmt.Errorf("failed to parse name \"%s\" (%v)", n.Name, err)
	}
	return ncryptAlgorithmName{
		Name:          nameUtf16Ptr,
		Class:         n.Class,
		AlgOperations: n.AlgOperations,
		Flags:         n.Flags,
	}, nil
}

// This is the actual golang equivalent of Windows NcryptKeyName.
type ncryptKeyName struct {
	Name          *uint16
	Alg           *uint16
	LegacyKeySpec NcryptLegacyKeySpec
	Flags         uint32
}

type NcryptKeyInfo struct {
	Name          string
	Alg           NcryptAlgorithm
	LegacyKeySpec NcryptLegacyKeySpec
	Flags         uint32
}

func (n *NcryptKeyInfo) fromInternal(internalNcryptKeyName ncryptKeyName) {
	n.Name = utf16PtrToString(internalNcryptKeyName.Name)
	n.Alg = NcryptAlgorithm(utf16PtrToString(internalNcryptKeyName.Alg))
	n.LegacyKeySpec = internalNcryptKeyName.LegacyKeySpec
	n.Flags = internalNcryptKeyName.Flags
}
func (n *NcryptKeyInfo) toInternal() (ncryptKeyName, error) {
	nameUtf16Ptr, err := stringToUtf16Ptr(n.Name)
	if err != nil {
		return ncryptKeyName{}, fmt.Errorf("failed to parse name \"%s\" (%v)", n.Name, err)
	}
	algUtf16Ptr, err := stringToUtf16Ptr(string(n.Alg))
	if err != nil {
		return ncryptKeyName{}, fmt.Errorf("failed to parse alg \"%s\" (%v)", n.Alg, err)
	}
	return ncryptKeyName{
		Name:          nameUtf16Ptr,
		Alg:           algUtf16Ptr,
		LegacyKeySpec: n.LegacyKeySpec,
		Flags:         n.Flags,
	}, nil
}

// This is the actual golang equivalent of Windows NcryptProviderName.
type ncryptProviderName struct {
	Name    *uint16
	Comment *uint16
}

type NcryptProviderInfo struct {
	Name    string
	Comment string
}

func (n *NcryptProviderInfo) fromInternal(internalNcryptProviderName ncryptProviderName) {
	n.Name = utf16PtrToString(internalNcryptProviderName.Name)
	n.Comment = utf16PtrToString(internalNcryptProviderName.Comment)
}
func (n *NcryptProviderInfo) toInternal() (ncryptProviderName, error) {
	nameUtf16Ptr, err := stringToUtf16Ptr(n.Name)
	if err != nil {
		return ncryptProviderName{}, fmt.Errorf("failed to parse name \"%s\" (%v)", n.Name, err)
	}
	commentUtf16Ptr, err := stringToUtf16Ptr(string(n.Comment))
	if err != nil {
		return ncryptProviderName{}, fmt.Errorf("failed to parse comment \"%s\" (%v)", n.Comment, err)
	}
	return ncryptProviderName{
		Name:    nameUtf16Ptr,
		Comment: commentUtf16Ptr,
	}, nil
}

// This is the actual golang equivalent of Windows NcryptUiPolicy.
type ncryptUiPolicy struct {
	Version       uint32
	Flags         uint32
	CreationTitle *uint16
	FriendlyName  *uint16
	Description   *uint16
}

type NcryptUiPolicy struct {
	Version       uint32
	Flags         NcryptUiPolicyPropertyFlag
	CreationTitle string
	FriendlyName  string
	Description   string
}

func (n *NcryptUiPolicy) serialize() ([]byte, error) {
	buf := new(bytes.Buffer)

	if err := binary.Write(buf, binary.LittleEndian, n.Version); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.LittleEndian, n.Flags); err != nil {
		return nil, err
	}

	for _, str := range []string{n.CreationTitle, n.FriendlyName, n.Description} {
		if err := binary.Write(buf, binary.LittleEndian, uint32(len(str))); err != nil {
			return nil, err
		}
		if err := binary.Write(buf, binary.LittleEndian, []byte(str)); err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}
func (n *NcryptUiPolicy) deserialize(data []byte) error {
	buf := bytes.NewReader(data)

	if err := binary.Read(buf, binary.LittleEndian, &n.Version); err != nil {
		return err
	}
	if err := binary.Read(buf, binary.LittleEndian, &n.Flags); err != nil {
		return err
	}

	var length uint32
	for i := 0; i < 3; i++ {
		if err := binary.Read(buf, binary.LittleEndian, &length); err != nil {
			return err
		}
		strBytes := make([]byte, length)
		if err := binary.Read(buf, binary.LittleEndian, &strBytes); err != nil {
			return err
		}
		switch i {
		case 0:
			n.CreationTitle = string(strBytes)
		case 1:
			n.FriendlyName = string(strBytes)
		case 2:
			n.Description = string(strBytes)
		}
	}

	return nil
}
func (n *NcryptUiPolicy) fromInternal(internalNcryptUiPolicy ncryptUiPolicy) {
	n.Version = internalNcryptUiPolicy.Version
	n.Flags = NcryptUiPolicyPropertyFlag(internalNcryptUiPolicy.Flags)
	n.CreationTitle = utf16PtrToString(internalNcryptUiPolicy.CreationTitle)
	n.FriendlyName = utf16PtrToString(internalNcryptUiPolicy.FriendlyName)
	n.Description = utf16PtrToString(internalNcryptUiPolicy.Description)
}
func (n *NcryptUiPolicy) toInternal() (ncryptUiPolicy, error) {
	creationTitleUtf16Ptr, err := stringToUtf16Ptr(n.CreationTitle)
	if err != nil {
		return ncryptUiPolicy{}, fmt.Errorf("failed to parse creation title \"%s\" (%v)", n.CreationTitle, err)
	}
	friendlyNameUtf16Ptr, err := stringToUtf16Ptr(n.FriendlyName)
	if err != nil {
		return ncryptUiPolicy{}, fmt.Errorf("failed to parse friendly name \"%s\" (%v)", n.FriendlyName, err)
	}
	descriptionUtf16Ptr, err := stringToUtf16Ptr(n.Description)
	if err != nil {
		return ncryptUiPolicy{}, fmt.Errorf("failed to parse description \"%s\" (%v)", n.Description, err)
	}
	return ncryptUiPolicy{
		Version:       n.Version,
		Flags:         uint32(n.Flags),
		CreationTitle: creationTitleUtf16Ptr,
		FriendlyName:  friendlyNameUtf16Ptr,
		Description:   descriptionUtf16Ptr,
	}, nil
}

type NcryptKeyAccessPolicyBlob struct {
	Version           uint32
	PolicyFlags       uint32
	UserSidLen        uint32
	ApplicationSidLen uint32
	//  User Sid
	//  Application Sid
}

// NCRYPT_LENGTHS_PROPERTY property structure.
type NcryptSupportedLengths struct {
	MinLength     uint32
	MaxLength     uint32
	Increment     uint32
	DefaultLength uint32
}

// NCRYPT_PCP_HMAC_AUTH_SIGNATURE property structure.
type NcryptPcpHmacAuthSignatureInfo struct {
	Version      uint32
	IExpiration  int32
	PabNonce     [32]byte
	PabPolicyRef [32]byte
	PabHMAC      [32]byte
}

// NCRYPT_PCP_TPM_FW_VERSION property structure.
type NcryptPcpTpmFwVersionInfo struct {
	Major1 uint16
	Major2 uint16
	Minor1 uint16
	Minor2 uint16
}

// NCRYPT_PCP_RAW_POLICYDIGEST_PROPERTY structure
type NcryptPcpRawPolicydigest struct {
	Version   uint32
	DigestLen uint32
}

type NcryptKeyBlobHeader struct {
	Size       uint32 // size of this structure
	Magic      NcryptMagic
	AlgNameLen uint32 // size of the algorithm, in bytes, including terminating 0
	KeyDataLen uint32
}

type NcryptTpmLoadableKeyBlobHeader struct {
	Magic      NcryptMagic
	HeaderLen  uint32
	PublicLen  uint32
	PrivateLen uint32
	NameLen    uint32
}

type NcryptLegacyKeySpec uint32

const (
	None          NcryptLegacyKeySpec = 0
	AtKeyExchange NcryptLegacyKeySpec = 1
	AtSignature   NcryptLegacyKeySpec = 2
)

func (s *NcryptLegacyKeySpec) String() string {
	if *s == None {
		return "None"
	} else if *s == AtKeyExchange {
		return "KeyExchange"
	} else if *s == AtSignature {
		return "Signature"
	} else {
		return "N/A"
	}
}

//////////////////////////////////////////////////////////////////////////////////////
// DLL references.
//////////////////////////////////////////////////////////////////////////////////////

var (
	kernel32 *windows.DLL
	nCrypt   *windows.DLL

	getProcAddressProc *windows.Proc

	nCryptCreateClaimProc          *windows.Proc
	nCryptCreatePersistedKeyProc   *windows.Proc
	nCryptDecryptProc              *windows.Proc
	nCryptDeleteKeyProc            *windows.Proc
	nCryptDeriveKeyProc            *windows.Proc
	nCryptEncryptProc              *windows.Proc
	nCryptEnumAlgorithmsProc       *windows.Proc
	nCryptEnumKeysProc             *windows.Proc
	nCryptEnumStorageProvidersProc *windows.Proc
	nCryptExportKeyProc            *windows.Proc
	nCryptFinalizeKeyProc          *windows.Proc
	nCryptFreeBufferProc           *windows.Proc
	nCryptFreeObjectProc           *windows.Proc
	nCryptGetPropertyProc          *windows.Proc
	nCryptImportKeyProc            *windows.Proc
	nCryptIsAlgSupportedProc       *windows.Proc
	nCryptIsKeyHandleProc          *windows.Proc
	nCryptKeyDerivationProc        *windows.Proc
	nCryptNotifyChangeKeyProc      *windows.Proc
	nCryptOpenKeyProc              *windows.Proc
	nCryptOpenStorageProviderProc  *windows.Proc
	nCryptSecretAgreementProc      *windows.Proc
	nCryptSetPropertyProc          *windows.Proc
	nCryptSignHashProc             *windows.Proc
	nCryptTranslateHandleProc      *windows.Proc
	nCryptVerifyClaimProc          *windows.Proc
	nCryptVerifySignatureProc      *windows.Proc

	nCryptProcs = map[string]**windows.Proc{
		"NCryptCreateClaim":          &nCryptCreateClaimProc,
		"NCryptCreatePersistedKey":   &nCryptCreatePersistedKeyProc,
		"NCryptDecrypt":              &nCryptDecryptProc,
		"NCryptDeleteKey":            &nCryptDeleteKeyProc,
		"NCryptDeriveKey":            &nCryptDeriveKeyProc,
		"NCryptEncrypt":              &nCryptEncryptProc,
		"NCryptEnumAlgorithms":       &nCryptEnumAlgorithmsProc,
		"NCryptEnumKeys":             &nCryptEnumKeysProc,
		"NCryptEnumStorageProviders": &nCryptEnumStorageProvidersProc,
		"NCryptExportKey":            &nCryptExportKeyProc,
		"NCryptFinalizeKey":          &nCryptFinalizeKeyProc,
		"NCryptFreeBuffer":           &nCryptFreeBufferProc,
		"NCryptFreeObject":           &nCryptFreeObjectProc,
		"NCryptGetProperty":          &nCryptGetPropertyProc,
		"NCryptImportKey":            &nCryptImportKeyProc,
		"NCryptIsAlgSupported":       &nCryptIsAlgSupportedProc,
		"NCryptIsKeyHandle":          &nCryptIsKeyHandleProc,
		"NCryptKeyDerivation":        &nCryptKeyDerivationProc,
		"NCryptNotifyChangeKey":      &nCryptNotifyChangeKeyProc,
		"NCryptOpenKey":              &nCryptOpenKeyProc,
		"NCryptOpenStorageProvider":  &nCryptOpenStorageProviderProc,
		"NCryptSecretAgreement":      &nCryptSecretAgreementProc,
		"NCryptSetProperty":          &nCryptSetPropertyProc,
		"NCryptSignHash":             &nCryptSignHashProc,
		"NCryptTranslateHandle":      &nCryptTranslateHandleProc,
		"NCryptVerifyClaim":          &nCryptVerifyClaimProc,
		"NCryptVerifySignature":      &nCryptVerifySignatureProc,
	}
)

// Initialize is the very first function that must be called
// on goncrypt. It ensures that the underlying ncrypt library and all
// its functions are loaded.
//
// If customLogger is nil, the library will use its default logger
// which will print log messages to stderr using INFO log level.
// To disable logging, a NewDefaultLogger can be passed with LogLevel
// set to LogLevelNone.
func Initialize(customLogger Logger) (errRet error) {
	if nCrypt == nil {
		// Set logger.
		if customLogger != nil {
			logger = customLogger
		}

		defer func() {
			if errRet != nil {
				logger.Error(errRet)
			}
		}()

		// Get System32 directory.
		systemDirPath, err := windows.GetSystemDirectory()
		if err != nil {
			errRet = fmt.Errorf("failed to get system directory: %v", err)
			return
		}
		logger.Debugf("Using system directory \"%s\"", systemDirPath)

		// Load kernel32 dll to get GetProcAddress.
		kernel32Lib := systemDirPath + "\\kernel32.dll"
		logger.Debugf("Loading Kernel32 at \"%s\"", kernel32Lib)
		kernel32, err = windows.LoadDLL(kernel32Lib)
		if err != nil {
			errRet = fmt.Errorf("could not load kernel32 library (%v)", err)
			return
		}
		getProcAddressProc, err = kernel32.FindProc("GetProcAddress")
		if err != nil {
			errRet = fmt.Errorf("could not find \"GetProcAddress\" in kernel32 library (%v)", err)
			return
		}

		// Load ncrypt.dll.
		nCryptLibPath := filepath.Join(systemDirPath, "Ncrypt.dll")
		logger.Debugf("Loading Ncrypt at \"%s\"", nCryptLibPath)
		nCrypt, err = windows.LoadDLL(nCryptLibPath)
		if err != nil {
			logger.Errorf("Failed to load Ncrypt at \"%s\" (%v)", nCryptLibPath, err)
		} else if nCrypt == nil {
			logger.Errorf("Ncrypt loaded at \"%s\" is nil (%v)", nCryptLibPath, err)
		}
		if nCrypt == nil {
			errRet = fmt.Errorf("could not load Ncrypt library")
			return
		}

		// Find ncrypt functions.
		for nCryptProcName, nCryptProc := range nCryptProcs {
			nCryptProcNamePtr, err := windows.BytePtrFromString(nCryptProcName)
			if err != nil {
				logger.Errorf("Could not parse proc name \"%s\" (%v)", nCryptProcName, err)
			} else {
				r, _, err := getProcAddressProc.Call(
					uintptr(nCrypt.Handle),
					uintptr(unsafe.Pointer(nCryptProcNamePtr)))
				if r != 0 {
					// FindProc performs GetProcAddress internally.
					// Therefore, we do not need to perform error checking
					// if our GetProcAddress succeeds.
					*nCryptProc, _ = nCrypt.FindProc(nCryptProcName)
				} else if err != nil {
					if err == windows.ERROR_PROC_NOT_FOUND {
						logger.Warnf("Could not find \"%s\"", nCryptProcName)
					} else {
						logger.Errorf("Failed to find \"%s\" (%v)", nCryptProcName, err)
					}
				}
			}
		}

		return
	} else {
		errRet = fmt.Errorf("goncrypt already initialized")
		return
	}
}

// Finalize is the very last function that must be called
// on goncrypt. It ensures that the previously loaded
// ncrypt library and functions are unloaded.
func Finalize() {
	if kernel32 != nil {
		kernel32.Release()
		kernel32 = nil
	}

	if nCrypt != nil {
		nCrypt.Release()
		nCrypt = nil

		getProcAddressProc = nil
		nCryptCreateClaimProc = nil
		nCryptCreatePersistedKeyProc = nil
		nCryptDecryptProc = nil
		nCryptDeleteKeyProc = nil
		nCryptDeriveKeyProc = nil
		nCryptEncryptProc = nil
		nCryptEnumAlgorithmsProc = nil
		nCryptEnumKeysProc = nil
		nCryptEnumStorageProvidersProc = nil
		nCryptExportKeyProc = nil
		nCryptFinalizeKeyProc = nil
		nCryptFreeBufferProc = nil
		nCryptFreeObjectProc = nil
		nCryptGetPropertyProc = nil
		nCryptImportKeyProc = nil
		nCryptIsAlgSupportedProc = nil
		nCryptIsKeyHandleProc = nil
		nCryptKeyDerivationProc = nil
		nCryptNotifyChangeKeyProc = nil
		nCryptOpenKeyProc = nil
		nCryptOpenStorageProviderProc = nil
		nCryptSecretAgreementProc = nil
		nCryptSetPropertyProc = nil
		nCryptSignHashProc = nil
		nCryptTranslateHandleProc = nil
		nCryptVerifyClaimProc = nil
		nCryptVerifySignatureProc = nil
	}
}

//////////////////////////////////////////////////////////////////////////////////////
// Windows error codes.
// From C:\Program Files (x86)\Windows Kits\10\Include\10.0.19041.0\shared\winerror.h.
//////////////////////////////////////////////////////////////////////////////////////

var (
	// TPM Services and TPM Software Error Codes.
	tpmErrNums = map[uint64]string{
		0x80280000: "TPM_E_ERROR_MASK",
		0x80280001: "TPM_E_AUTHFAIL",
		0x80280002: "TPM_E_BADINDEX",
		0x80280003: "TPM_E_BAD_PARAMETER",
		0x80280004: "TPM_E_AUDITFAILURE",
		0x80280005: "TPM_E_CLEAR_DISABLED",
		0x80280006: "TPM_E_DEACTIVATED",
		0x80280007: "TPM_E_DISABLED",
		0x80280008: "TPM_E_DISABLED_CMD",
		0x80280009: "TPM_E_FAIL",
		0x8028000A: "TPM_E_BAD_ORDINAL",
		0x8028000B: "TPM_E_INSTALL_DISABLED",
		0x8028000C: "TPM_E_INVALID_KEYHANDLE",
		0x8028000D: "TPM_E_KEYNOTFOUND",
		0x8028000E: "TPM_E_INAPPROPRIATE_ENC",
		0x8028000F: "TPM_E_MIGRATEFAIL",
		0x80280010: "TPM_E_INVALID_PCR_INFO",
		0x80280011: "TPM_E_NOSPACE",
		0x80280012: "TPM_E_NOSRK",
		0x80280013: "TPM_E_NOTSEALED_BLOB",
		0x80280014: "TPM_E_OWNER_SET",
		0x80280015: "TPM_E_RESOURCES",
		0x80280016: "TPM_E_SHORTRANDOM",
		0x80280017: "TPM_E_SIZE",
		0x80280018: "TPM_E_WRONGPCRVAL",
		0x80280019: "TPM_E_BAD_PARAM_SIZE",
		0x8028001A: "TPM_E_SHA_THREAD",
		0x8028001B: "TPM_E_SHA_ERROR",
		0x8028001C: "TPM_E_FAILEDSELFTEST",
		0x8028001D: "TPM_E_AUTH2FAIL",
		0x8028001E: "TPM_E_BADTAG",
		0x8028001F: "TPM_E_IOERROR",
		0x80280020: "TPM_E_ENCRYPT_ERROR",
		0x80280021: "TPM_E_DECRYPT_ERROR",
		0x80280022: "TPM_E_INVALID_AUTHHANDLE",
		0x80280023: "TPM_E_NO_ENDORSEMENT",
		0x80280024: "TPM_E_INVALID_KEYUSAGE",
		0x80280025: "TPM_E_WRONG_ENTITYTYPE",
		0x80280026: "TPM_E_INVALID_POSTINIT",
		0x80280027: "TPM_E_INAPPROPRIATE_SIG",
		0x80280028: "TPM_E_BAD_KEY_PROPERTY",
		0x80280029: "TPM_E_BAD_MIGRATION",
		0x8028002A: "TPM_E_BAD_SCHEME",
		0x8028002B: "TPM_E_BAD_DATASIZE",
		0x8028002C: "TPM_E_BAD_MODE",
		0x8028002D: "TPM_E_BAD_PRESENCE",
		0x8028002E: "TPM_E_BAD_VERSION",
		0x8028002F: "TPM_E_NO_WRAP_TRANSPORT",
		0x80280030: "TPM_E_AUDITFAIL_UNSUCCESSFUL",
		0x80280031: "TPM_E_AUDITFAIL_SUCCESSFUL",
		0x80280032: "TPM_E_NOTRESETABLE",
		0x80280033: "TPM_E_NOTLOCAL",
		0x80280034: "TPM_E_BAD_TYPE",
		0x80280035: "TPM_E_INVALID_RESOURCE",
		0x80280036: "TPM_E_NOTFIPS",
		0x80280037: "TPM_E_INVALID_FAMILY",
		0x80280038: "TPM_E_NO_NV_PERMISSION",
		0x80280039: "TPM_E_REQUIRES_SIGN",
		0x8028003A: "TPM_E_KEY_NOTSUPPORTED",
		0x8028003B: "TPM_E_AUTH_CONFLICT",
		0x8028003C: "TPM_E_AREA_LOCKED",
		0x8028003D: "TPM_E_BAD_LOCALITY",
		0x8028003E: "TPM_E_READ_ONLY",
		0x8028003F: "TPM_E_PER_NOWRITE",
		0x80280040: "TPM_E_FAMILYCOUNT",
		0x80280041: "TPM_E_WRITE_LOCKED",
		0x80280042: "TPM_E_BAD_ATTRIBUTES",
		0x80280043: "TPM_E_INVALID_STRUCTURE",
		0x80280044: "TPM_E_KEY_OWNER_CONTROL",
		0x80280045: "TPM_E_BAD_COUNTER",
		0x80280046: "TPM_E_NOT_FULLWRITE",
		0x80280047: "TPM_E_CONTEXT_GAP",
		0x80280048: "TPM_E_MAXNVWRITES",
		0x80280049: "TPM_E_NOOPERATOR",
		0x8028004A: "TPM_E_RESOURCEMISSING",
		0x8028004B: "TPM_E_DELEGATE_LOCK",
		0x8028004C: "TPM_E_DELEGATE_FAMILY",
		0x8028004D: "TPM_E_DELEGATE_ADMIN",
		0x8028004E: "TPM_E_TRANSPORT_NOTEXCLUSIVE",
		0x8028004F: "TPM_E_OWNER_CONTROL",
		0x80280050: "TPM_E_DAA_RESOURCES",
		0x80280051: "TPM_E_DAA_INPUT_DATA0",
		0x80280052: "TPM_E_DAA_INPUT_DATA1",
		0x80280053: "TPM_E_DAA_ISSUER_SETTINGS",
		0x80280054: "TPM_E_DAA_TPM_SETTINGS",
		0x80280055: "TPM_E_DAA_STAGE",
		0x80280056: "TPM_E_DAA_ISSUER_VALIDITY",
		0x80280057: "TPM_E_DAA_WRONG_W",
		0x80280058: "TPM_E_BAD_HANDLE",
		0x80280059: "TPM_E_BAD_DELEGATE",
		0x8028005A: "TPM_E_BADCONTEXT",
		0x8028005B: "TPM_E_TOOMANYCONTEXTS",
		0x8028005C: "TPM_E_MA_TICKET_SIGNATURE",
		0x8028005D: "TPM_E_MA_DESTINATION",
		0x8028005E: "TPM_E_MA_SOURCE",
		0x8028005F: "TPM_E_MA_AUTHORITY",
		0x80280061: "TPM_E_PERMANENTEK",
		0x80280062: "TPM_E_BAD_SIGNATURE",
		0x80280063: "TPM_E_NOCONTEXTSPACE",
		0x80280081: "TPM_20_E_ASYMMETRIC",
		0x80280082: "TPM_20_E_ATTRIBUTES",
		0x80280083: "TPM_20_E_HASH",
		0x80280084: "TPM_20_E_VALUE",
		0x80280085: "TPM_20_E_HIERARCHY",
		0x80280087: "TPM_20_E_KEY_SIZE",
		0x80280088: "TPM_20_E_MGF",
		0x80280089: "TPM_20_E_MODE",
		0x8028008A: "TPM_20_E_TYPE",
		0x8028008B: "TPM_20_E_HANDLE",
		0x8028008C: "TPM_20_E_KDF",
		0x8028008D: "TPM_20_E_RANGE",
		0x8028008E: "TPM_20_E_AUTH_FAIL",
		0x8028008F: "TPM_20_E_NONCE",
		0x80280090: "TPM_20_E_PP",
		0x80280092: "TPM_20_E_SCHEME",
		0x80280095: "TPM_20_E_SIZE",
		0x80280096: "TPM_20_E_SYMMETRIC",
		0x80280097: "TPM_20_E_TAG",
		0x80280098: "TPM_20_E_SELECTOR",
		0x8028009A: "TPM_20_E_INSUFFICIENT",
		0x8028009B: "TPM_20_E_SIGNATURE",
		0x8028009C: "TPM_20_E_KEY",
		0x8028009D: "TPM_20_E_POLICY_FAIL",
		0x8028009F: "TPM_20_E_INTEGRITY",
		0x802800A0: "TPM_20_E_TICKET",
		0x802800A1: "TPM_20_E_RESERVED_BITS",
		0x802800A2: "TPM_20_E_BAD_AUTH",
		0x802800A3: "TPM_20_E_EXPIRED",
		0x802800A4: "TPM_20_E_POLICY_CC",
		0x802800A5: "TPM_20_E_BINDING",
		0x802800A6: "TPM_20_E_CURVE",
		0x802800A7: "TPM_20_E_ECC_POINT",
		0x80280100: "TPM_20_E_INITIALIZE",
		0x80280101: "TPM_20_E_FAILURE",
		0x80280103: "TPM_20_E_SEQUENCE",
		0x8028010B: "TPM_20_E_PRIVATE",
		0x80280119: "TPM_20_E_HMAC",
		0x80280120: "TPM_20_E_DISABLED",
		0x80280121: "TPM_20_E_EXCLUSIVE",
		0x80280123: "TPM_20_E_ECC_CURVE",
		0x80280124: "TPM_20_E_AUTH_TYPE",
		0x80280125: "TPM_20_E_AUTH_MISSING",
		0x80280126: "TPM_20_E_POLICY",
		0x80280127: "TPM_20_E_PCR",
		0x80280128: "TPM_20_E_PCR_CHANGED",
		0x8028012D: "TPM_20_E_UPGRADE",
		0x8028012E: "TPM_20_E_TOO_MANY_CONTEXTS",
		0x8028012F: "TPM_20_E_AUTH_UNAVAILABLE",
		0x80280130: "TPM_20_E_REBOOT",
		0x80280131: "TPM_20_E_UNBALANCED",
		0x80280142: "TPM_20_E_COMMAND_SIZE",
		0x80280143: "TPM_20_E_COMMAND_CODE",
		0x80280144: "TPM_20_E_AUTHSIZE",
		0x80280145: "TPM_20_E_AUTH_CONTEXT",
		0x80280146: "TPM_20_E_NV_RANGE",
		0x80280147: "TPM_20_E_NV_SIZE",
		0x80280148: "TPM_20_E_NV_LOCKED",
		0x80280149: "TPM_20_E_NV_AUTHORIZATION",
		0x8028014A: "TPM_20_E_NV_UNINITIALIZED",
		0x8028014B: "TPM_20_E_NV_SPACE",
		0x8028014C: "TPM_20_E_NV_DEFINED",
		0x80280150: "TPM_20_E_BAD_CONTEXT",
		0x80280151: "TPM_20_E_CPHASH",
		0x80280152: "TPM_20_E_PARENT",
		0x80280153: "TPM_20_E_NEEDS_TEST",
		0x80280154: "TPM_20_E_NO_RESULT",
		0x80280155: "TPM_20_E_SENSITIVE",
		0x80280400: "TPM_E_COMMAND_BLOCKED",
		0x80280401: "TPM_E_INVALID_HANDLE",
		0x80280402: "TPM_E_DUPLICATE_VHANDLE",
		0x80280403: "TPM_E_EMBEDDED_COMMAND_BLOCKED",
		0x80280404: "TPM_E_EMBEDDED_COMMAND_UNSUPPORTED",
		0x80280800: "TPM_E_RETRY",
		0x80280801: "TPM_E_NEEDS_SELFTEST",
		0x80280802: "TPM_E_DOING_SELFTEST",
		0x80280803: "TPM_E_DEFEND_LOCK_RUNNING",
		0x80280901: "TPM_20_E_CONTEXT_GAP",
		0x80280902: "TPM_20_E_OBJECT_MEMORY",
		0x80280903: "TPM_20_E_SESSION_MEMORY",
		0x80280904: "TPM_20_E_MEMORY",
		0x80280905: "TPM_20_E_SESSION_HANDLES",
		0x80280906: "TPM_20_E_OBJECT_HANDLES",
		0x80280907: "TPM_20_E_LOCALITY",
		0x80280908: "TPM_20_E_YIELDED",
		0x80280909: "TPM_20_E_CANCELED",
		0x8028090A: "TPM_20_E_TESTING",
		0x80280920: "TPM_20_E_NV_RATE",
		0x80280921: "TPM_20_E_LOCKOUT",
		0x80280922: "TPM_20_E_RETRY",
		0x80280923: "TPM_20_E_NV_UNAVAILABLE",
		0x80284001: "TBS_E_INTERNAL_ERROR",
		0x80284002: "TBS_E_BAD_PARAMETER",
		0x80284003: "TBS_E_INVALID_OUTPUT_POINTER",
		0x80284004: "TBS_E_INVALID_CONTEXT",
		0x80284005: "TBS_E_INSUFFICIENT_BUFFER",
		0x80284006: "TBS_E_IOERROR",
		0x80284007: "TBS_E_INVALID_CONTEXT_PARAM",
		0x80284008: "TBS_E_SERVICE_NOT_RUNNING",
		0x80284009: "TBS_E_TOO_MANY_TBS_CONTEXTS",
		0x8028400A: "TBS_E_TOO_MANY_RESOURCES",
		0x8028400B: "TBS_E_SERVICE_START_PENDING",
		0x8028400C: "TBS_E_PPI_NOT_SUPPORTED",
		0x8028400D: "TBS_E_COMMAND_CANCELED",
		0x8028400E: "TBS_E_BUFFER_TOO_LARGE",
		0x8028400F: "TBS_E_TPM_NOT_FOUND",
		0x80284010: "TBS_E_SERVICE_DISABLED",
		0x80284011: "TBS_E_NO_EVENT_LOG",
		0x80284012: "TBS_E_ACCESS_DENIED",
		0x80284013: "TBS_E_PROVISIONING_NOT_ALLOWED",
		0x80284014: "TBS_E_PPI_FUNCTION_UNSUPPORTED",
		0x80284015: "TBS_E_OWNERAUTH_NOT_FOUND",
		0x80284016: "TBS_E_PROVISIONING_INCOMPLETE",
		0x80290100: "TPMAPI_E_INVALID_STATE",
		0x80290101: "TPMAPI_E_NOT_ENOUGH_DATA",
		0x80290102: "TPMAPI_E_TOO_MUCH_DATA",
		0x80290103: "TPMAPI_E_INVALID_OUTPUT_POINTER",
		0x80290104: "TPMAPI_E_INVALID_PARAMETER",
		0x80290105: "TPMAPI_E_OUT_OF_MEMORY",
		0x80290106: "TPMAPI_E_BUFFER_TOO_SMALL",
		0x80290107: "TPMAPI_E_INTERNAL_ERROR",
		0x80290108: "TPMAPI_E_ACCESS_DENIED",
		0x80290109: "TPMAPI_E_AUTHORIZATION_FAILED",
		0x8029010A: "TPMAPI_E_INVALID_CONTEXT_HANDLE",
		0x8029010B: "TPMAPI_E_TBS_COMMUNICATION_ERROR",
		0x8029010C: "TPMAPI_E_TPM_COMMAND_ERROR",
		0x8029010D: "TPMAPI_E_MESSAGE_TOO_LARGE",
		0x8029010E: "TPMAPI_E_INVALID_ENCODING",
		0x8029010F: "TPMAPI_E_INVALID_KEY_SIZE",
		0x80290110: "TPMAPI_E_ENCRYPTION_FAILED",
		0x80290111: "TPMAPI_E_INVALID_KEY_PARAMS",
		0x80290112: "TPMAPI_E_INVALID_MIGRATION_AUTHORIZATION_BLOB",
		0x80290113: "TPMAPI_E_INVALID_PCR_INDEX",
		0x80290114: "TPMAPI_E_INVALID_DELEGATE_BLOB",
		0x80290115: "TPMAPI_E_INVALID_CONTEXT_PARAMS",
		0x80290116: "TPMAPI_E_INVALID_KEY_BLOB",
		0x80290117: "TPMAPI_E_INVALID_PCR_DATA",
		0x80290118: "TPMAPI_E_INVALID_OWNER_AUTH",
		0x80290119: "TPMAPI_E_FIPS_RNG_CHECK_FAILED",
		0x8029011A: "TPMAPI_E_EMPTY_TCG_LOG",
		0x8029011B: "TPMAPI_E_INVALID_TCG_LOG_ENTRY",
		0x8029011C: "TPMAPI_E_TCG_SEPARATOR_ABSENT",
		0x8029011D: "TPMAPI_E_TCG_INVALID_DIGEST_ENTRY",
		0x8029011E: "TPMAPI_E_POLICY_DENIES_OPERATION",
		0x8029011F: "TPMAPI_E_NV_BITS_NOT_DEFINED",
		0x80290120: "TPMAPI_E_NV_BITS_NOT_READY",
		0x80290121: "TPMAPI_E_SEALING_KEY_NOT_AVAILABLE",
		0x80290122: "TPMAPI_E_NO_AUTHORIZATION_CHAIN_FOUND",
		0x80290123: "TPMAPI_E_SVN_COUNTER_NOT_AVAILABLE",
		0x80290124: "TPMAPI_E_OWNER_AUTH_NOT_NULL",
		0x80290125: "TPMAPI_E_ENDORSEMENT_AUTH_NOT_NULL",
		0x80290126: "TPMAPI_E_AUTHORIZATION_REVOKED",
		0x80290127: "TPMAPI_E_MALFORMED_AUTHORIZATION_KEY",
		0x80290128: "TPMAPI_E_AUTHORIZING_KEY_NOT_SUPPORTED",
		0x80290129: "TPMAPI_E_INVALID_AUTHORIZATION_SIGNATURE",
		0x8029012A: "TPMAPI_E_MALFORMED_AUTHORIZATION_POLICY",
		0x8029012B: "TPMAPI_E_MALFORMED_AUTHORIZATION_OTHER",
		0x8029012C: "TPMAPI_E_SEALING_KEY_CHANGED",
		0x8029012D: "TPMAPI_E_INVALID_TPM_VERSION",
		0x8029012E: "TPMAPI_E_INVALID_POLICYAUTH_BLOB_TYPE",
		0x80290200: "TBSIMP_E_BUFFER_TOO_SMALL",
		0x80290201: "TBSIMP_E_CLEANUP_FAILED",
		0x80290202: "TBSIMP_E_INVALID_CONTEXT_HANDLE",
		0x80290203: "TBSIMP_E_INVALID_CONTEXT_PARAM",
		0x80290204: "TBSIMP_E_TPM_ERROR",
		0x80290205: "TBSIMP_E_HASH_BAD_KEY",
		0x80290206: "TBSIMP_E_DUPLICATE_VHANDLE",
		0x80290207: "TBSIMP_E_INVALID_OUTPUT_POINTER",
		0x80290208: "TBSIMP_E_INVALID_PARAMETER",
		0x80290209: "TBSIMP_E_RPC_INIT_FAILED",
		0x8029020A: "TBSIMP_E_SCHEDULER_NOT_RUNNING",
		0x8029020B: "TBSIMP_E_COMMAND_CANCELED",
		0x8029020C: "TBSIMP_E_OUT_OF_MEMORY",
		0x8029020D: "TBSIMP_E_LIST_NO_MORE_ITEMS",
		0x8029020E: "TBSIMP_E_LIST_NOT_FOUND",
		0x8029020F: "TBSIMP_E_NOT_ENOUGH_SPACE",
		0x80290210: "TBSIMP_E_NOT_ENOUGH_TPM_CONTEXTS",
		0x80290211: "TBSIMP_E_COMMAND_FAILED",
		0x80290212: "TBSIMP_E_UNKNOWN_ORDINAL",
		0x80290213: "TBSIMP_E_RESOURCE_EXPIRED",
		0x80290214: "TBSIMP_E_INVALID_RESOURCE",
		0x80290215: "TBSIMP_E_NOTHING_TO_UNLOAD",
		0x80290216: "TBSIMP_E_HASH_TABLE_FULL",
		0x80290217: "TBSIMP_E_TOO_MANY_TBS_CONTEXTS",
		0x80290218: "TBSIMP_E_TOO_MANY_RESOURCES",
		0x80290219: "TBSIMP_E_PPI_NOT_SUPPORTED",
		0x8029021A: "TBSIMP_E_TPM_INCOMPATIBLE",
		0x8029021B: "TBSIMP_E_NO_EVENT_LOG",
		0x80290300: "TPM_E_PPI_ACPI_FAILURE",
		0x80290301: "TPM_E_PPI_USER_ABORT",
		0x80290302: "TPM_E_PPI_BIOS_FAILURE",
		0x80290303: "TPM_E_PPI_NOT_SUPPORTED",
		0x80290304: "TPM_E_PPI_BLOCKED_IN_BIOS",
		0x80290400: "TPM_E_PCP_ERROR_MASK",
		0x80290401: "TPM_E_PCP_DEVICE_NOT_READY",
		0x80290402: "TPM_E_PCP_INVALID_HANDLE",
		0x80290403: "TPM_E_PCP_INVALID_PARAMETER",
		0x80290404: "TPM_E_PCP_FLAG_NOT_SUPPORTED",
		0x80290405: "TPM_E_PCP_NOT_SUPPORTED",
		0x80290406: "TPM_E_PCP_BUFFER_TOO_SMALL",
		0x80290407: "TPM_E_PCP_INTERNAL_ERROR",
		0x80290408: "TPM_E_PCP_AUTHENTICATION_FAILED",
		0x80290409: "TPM_E_PCP_AUTHENTICATION_IGNORED",
		0x8029040A: "TPM_E_PCP_POLICY_NOT_FOUND",
		0x8029040B: "TPM_E_PCP_PROFILE_NOT_FOUND",
		0x8029040C: "TPM_E_PCP_VALIDATION_FAILED",
		0x8029040E: "TPM_E_PCP_WRONG_PARENT",
		0x8029040F: "TPM_E_KEY_NOT_LOADED",
		0x80290410: "TPM_E_NO_KEY_CERTIFICATION",
		0x80290411: "TPM_E_KEY_NOT_FINALIZED",
		0x80290412: "TPM_E_ATTESTATION_CHALLENGE_NOT_SET",
		0x80290413: "TPM_E_NOT_PCR_BOUND",
		0x80290414: "TPM_E_KEY_ALREADY_FINALIZED",
		0x80290415: "TPM_E_KEY_USAGE_POLICY_NOT_SUPPORTED",
		0x80290416: "TPM_E_KEY_USAGE_POLICY_INVALID",
		0x80290417: "TPM_E_SOFT_KEY_ERROR",
		0x80290418: "TPM_E_KEY_NOT_AUTHENTICATED",
		0x80290419: "TPM_E_PCP_KEY_NOT_AIK",
		0x8029041A: "TPM_E_KEY_NOT_SIGNING_KEY",
		0x8029041B: "TPM_E_LOCKED_OUT",
		0x8029041C: "TPM_E_CLAIM_TYPE_NOT_SUPPORTED",
		0x8029041D: "TPM_E_VERSION_NOT_SUPPORTED",
		0x8029041E: "TPM_E_BUFFER_LENGTH_MISMATCH",
		0x8029041F: "TPM_E_PCP_IFX_RSA_KEY_CREATION_BLOCKED",
		0x80290420: "TPM_E_PCP_TICKET_MISSING",
		0x80290421: "TPM_E_PCP_RAW_POLICY_NOT_SUPPORTED",
		0x80290422: "TPM_E_PCP_KEY_HANDLE_INVALIDATED",
		0x40290423: "TPM_E_PCP_UNSUPPORTED_PSS_SALT",
		0x40290424: "TPM_E_PCP_PLATFORM_CLAIM_MAY_BE_OUTDATED",
		0x40290425: "TPM_E_PCP_PLATFORM_CLAIM_OUTDATED",
		0x40290426: "TPM_E_PCP_PLATFORM_CLAIM_REBOOT",
		0x80290500: "TPM_E_ZERO_EXHAUST_ENABLED",
		0x80290600: "TPM_E_PROVISIONING_INCOMPLETE",
		0x80290601: "TPM_E_INVALID_OWNER_AUTH",
		0x80290602: "TPM_E_TOO_MUCH_DATA",
	}

	// Other Error Codes.
	otherWinErrNums = map[uint64]string{
		0x80090001: "NTE_BAD_UID",
		0x80090002: "NTE_BAD_HASH",
		0x80090003: "NTE_BAD_KEY",
		0x80090004: "NTE_BAD_LEN",
		0x80090005: "NTE_BAD_DATA",
		0x80090006: "NTE_BAD_SIGNATURE",
		0x80090007: "NTE_BAD_VER",
		0x80090008: "NTE_BAD_ALGID",
		0x80090009: "NTE_BAD_FLAGS",
		0x8009000A: "NTE_BAD_TYPE",
		0x8009000B: "NTE_BAD_KEY_STATE",
		0x8009000C: "NTE_BAD_HASH_STATE",
		0x8009000D: "NTE_NO_KEY",
		0x8009000E: "NTE_NO_MEMORY",
		0x8009000F: "NTE_EXISTS",
		0x80090010: "NTE_PERM",
		0x80090011: "NTE_NOT_FOUND",
		0x80090012: "NTE_DOUBLE_ENCRYPT",
		0x80090013: "NTE_BAD_PROVIDER",
		0x80090014: "NTE_BAD_PROV_TYPE",
		0x80090015: "NTE_BAD_PUBLIC_KEY",
		0x80090016: "NTE_BAD_KEYSET",
		0x80090017: "NTE_PROV_TYPE_NOT_DEF",
		0x80090018: "NTE_PROV_TYPE_ENTRY_BAD",
		0x80090019: "NTE_KEYSET_NOT_DEF",
		0x8009001A: "NTE_KEYSET_ENTRY_BAD",
		0x8009001B: "NTE_PROV_TYPE_NO_MATCH",
		0x8009001C: "NTE_SIGNATURE_FILE_BAD",
		0x8009001D: "NTE_PROVIDER_DLL_FAIL",
		0x8009001E: "NTE_PROV_DLL_NOT_FOUND",
		0x8009001F: "NTE_BAD_KEYSET_PARAM",
		0x80090020: "NTE_FAIL",
		0x80090021: "NTE_SYS_ERR",
		0x80090022: "NTE_SILENT_CONTEXT",
		0x80090023: "NTE_TOKEN_KEYSET_STORAGE_FULL",
		0x80090024: "NTE_TEMPORARY_PROFILE",
		0x80090025: "NTE_FIXEDPARAMETER",
		0x80090026: "NTE_INVALID_HANDLE",
		0x80090027: "NTE_INVALID_PARAMETER",
		0x80090028: "NTE_BUFFER_TOO_SMALL",
		0x80090029: "NTE_NOT_SUPPORTED",
		0x8009002A: "NTE_NO_MORE_ITEMS",
		0x8009002B: "NTE_BUFFERS_OVERLAP",
		0x8009002C: "NTE_DECRYPTION_FAILURE",
		0x8009002D: "NTE_INTERNAL_ERROR",
		0x8009002E: "NTE_UI_REQUIRED",
		0x8009002F: "NTE_HMAC_NOT_SUPPORTED",
		0x80090030: "NTE_DEVICE_NOT_READY",
		0x80090031: "NTE_AUTHENTICATION_IGNORED",
		0x80090032: "NTE_VALIDATION_FAILED",
		0x80090033: "NTE_INCORRECT_PASSWORD",
		0x80090034: "NTE_ENCRYPTION_FAILURE",
		0x80090035: "NTE_DEVICE_NOT_FOUND",
		0x80090036: "NTE_USER_CANCELLED",
		0x80090037: "NTE_PASSWORD_CHANGE_REQUIRED",
		0x80090038: "NTE_NOT_ACTIVE_CONSOLE",
	}
)

func maybeWinErr(errNo uintptr) error {
	if code, known := tpmErrNums[uint64(errNo)]; known {
		return fmt.Errorf("tpm or subsystem failure: (%X) %s", errNo, code)
	} else if code, known := otherWinErrNums[uint64(errNo)]; known {
		return fmt.Errorf("failure code: (%X) %s", errNo, code)
	} else {
		return fmt.Errorf("errno code: (%X) %s", errNo, syscall.Errno(errNo))
	}
}

//////////////////////////////////////////////////////////////////////////////////////
// NCrypt structs.
//////////////////////////////////////////////////////////////////////////////////////

// Provider represents a CNG Key Storage Provider.
type Provider struct {
	handle NcryptProvHandle
	name   string
}

func (p *Provider) Handle() NcryptProvHandle {
	return p.handle
}

func (p *Provider) Name() string {
	return p.name
}

// Key represents a CNG key.
type Key struct {
	handle NcryptKeyHandle
	name   string
	alg    NcryptAlgorithm
}

func (k *Key) Handle() NcryptKeyHandle {
	return k.handle
}

func (k *Key) Name() string {
	return k.name
}

func (k *Key) Alg() NcryptAlgorithm {
	return k.alg
}

// Secret represents a CNG Key Storage Provider
// secret agreement value.
type Secret struct {
	handle NcryptSecretHandle
}

func (s *Secret) Handle() NcryptSecretHandle {
	return s.handle
}

//////////////////////////////////////////////////////////////////////////////////////
// NCrypt functions.
//////////////////////////////////////////////////////////////////////////////////////

// EnumProviders is a wrapper around NCryptEnumStorageProviders.
//
// This function obtains the names of the registered
// CNG key storage providers.
func EnumProviders(
	flags NcryptFlag,
) (provsInfo []NcryptProviderInfo, ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	var providersCount uint32
	var providerListPtr *ncryptProviderName

	logger.Infof("EnumProviders, IN : (flags=0x%.8X)", flags)
	defer func() { logger.Infof("EnumProviders, OUT: (provsInfo=%v)", provsInfo) }()

	if nCryptEnumStorageProvidersProc == nil {
		err = fmt.Errorf("nCryptEnumStorageProvidersProc() not found in ncrypt.dll")
		return
	}

	r, _, msg := nCryptEnumStorageProvidersProc.Call(
		uintptr(unsafe.Pointer(&providersCount)),
		uintptr(unsafe.Pointer(&providerListPtr)),
		uintptr(flags),
	)
	if r != 0 {
		if winErr := maybeWinErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("nCryptEnumStorageProvidersProc() returned %X (%v)", r, msg)
		return
	}

	defer func() {
		if providerListPtr != nil {
			nCryptFreeBufferProc.Call(uintptr(unsafe.Pointer(providerListPtr)))
		}
	}()

	if providersCount > 0 {
		providerList := (*[1 << 30]ncryptProviderName)(unsafe.Pointer(providerListPtr))[:providersCount:providersCount]
		provsInfo = make([]NcryptProviderInfo, providersCount)
		for i := range provsInfo {
			provsInfo[i].fromInternal(providerList[i])
		}
	}

	return
}

// OpenProvider is a wrapper around NCryptOpenStorageProvider.
//
// This function loads and initializes a CNG key storage provider.
func OpenProvider(
	name string,
	flags NcryptFlag,
) (provider Provider, ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	handle := NcryptProvHandle(invalidHandleValue)
	provider.handle = NcryptProvHandle(invalidHandleValue)

	logger.Infof("OpenProvider, IN : (name=%s, flags=0x%.8X)", name, flags)
	defer func() { logger.Infof("OpenProvider, OUT: (provider=%v)", provider) }()

	if nCryptOpenStorageProviderProc == nil {
		err = fmt.Errorf("nCryptOpenStorageProvider() not found in ncrypt.dll")
		return
	}

	utf16ProviderName, err := stringToUtf16Ptr(name)
	if err != nil {
		err = fmt.Errorf("failed to parse provider name \"%s\" (%v)", name, err)
		return
	}

	r, _, msg := nCryptOpenStorageProviderProc.Call(
		uintptr(unsafe.Pointer(&handle)),
		uintptr(unsafe.Pointer(utf16ProviderName)),
		uintptr(flags),
	)
	if r != 0 {
		if winErr := maybeWinErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("nCryptOpenStorageProvider() returned %X (%v)", r, msg)
		return
	}

	provider.handle = handle
	provider.name = name

	return
}

// GetProperty is a wrapper around NCryptGetProperty for providers.
//
// This function retrieves the value of a named property for the
// specified CNG key storage provider.
func (p *Provider) GetProperty(
	propertyName NcryptProperty,
	flags NcryptFlag,
) (property []byte, ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	logger.Infof("GetProperty, IN : (provider=%v, propertyName=%s, flags=0x%.8X)", p, propertyName, flags)
	defer func() {
		logger.Infof("GetProperty, OUT: (provider=%v, propertyName=%s, property=%v)", p, propertyName, property)
	}()

	if nCryptGetPropertyProc == nil {
		err = fmt.Errorf("nCryptGetProperty() not found in ncrypt.dll")
		return
	}

	var size uint32

	utf16Property, err := stringToUtf16Ptr(string(propertyName))
	if err != nil {
		err = fmt.Errorf("failed to parse property \"%s\" (%v)", propertyName, err)
		return
	}

	r, _, msg := nCryptGetPropertyProc.Call(
		uintptr(p.handle),
		uintptr(unsafe.Pointer(utf16Property)),
		0,
		0,
		uintptr(unsafe.Pointer(&size)),
		uintptr(flags),
	)
	if r != 0 {
		if winErr := maybeWinErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("nCryptGetProperty() 1st call returned %X (%v)", r, msg)
		return
	}

	if size > 0 {
		property = make([]byte, size)
		r, _, msg = nCryptGetPropertyProc.Call(
			uintptr(p.handle),
			uintptr(unsafe.Pointer(utf16Property)),
			uintptr(unsafe.Pointer(&property[0])),
			uintptr(size),
			uintptr(unsafe.Pointer(&size)),
			uintptr(flags),
		)
		if r != 0 {
			if winErr := maybeWinErr(r); winErr != nil {
				msg = winErr
			}
			property = nil
			ret = uint64(r)
			err = fmt.Errorf("nCryptGetProperty() 2nd call returned %X (%v)", r, msg)
			return
		}

		if size > 0 {
			property = property[:size]
		}
	}

	return
}

// SetProperty is a wrapper around NCryptSetProperty for providers.
//
// This function sets the value for a named property for the
// specified CNG key storage provider.
func (p *Provider) SetProperty(
	propertyName NcryptProperty,
	property []byte,
	flags NcryptFlag,
) (ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	var propertyPtr *byte

	logger.Infof("SetProperty, IN : (provider=%v, propertyName=%s, property=%v, flags=0x%.8X)", p, propertyName, property, flags)
	defer func() { logger.Infof("SetProperty, OUT: (provider=%v, propertyName=%v)", p, propertyName) }()

	if nCryptSetPropertyProc == nil {
		err = fmt.Errorf("nCryptSetProperty() not found in ncrypt.dll")
		return
	}

	utf16PropertyName, err := stringToUtf16Ptr(string(propertyName))
	if err != nil {
		err = fmt.Errorf("failed to parse property \"%s\" (%v)", propertyName, err)
		return
	}

	if len(property) > 0 {
		propertyPtr = &property[0]
	}

	r, _, msg := nCryptSetPropertyProc.Call(
		uintptr(p.handle),
		uintptr(unsafe.Pointer(utf16PropertyName)),
		uintptr(unsafe.Pointer(propertyPtr)),
		uintptr(len(property)),
		uintptr(flags),
	)
	if r != 0 {
		if winErr := maybeWinErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("nCryptSetProperty() 1st call returned %X (%v)", r, msg)
		return
	}

	return
}

// EnumAlgorithms is a wrapper around NCryptEnumAlgorithms.
//
// This function obtains the names of the algorithms that are
// supported by the specified CNG key storage provider.
func (p *Provider) EnumAlgorithms(
	algOperations NcryptAlgOperation,
	flags NcryptFlag,
) (algsInfo []NcryptAlgorithmInfo, ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	var algCount uint32
	var algListPtr *ncryptAlgorithmName

	logger.Infof("EnumAlgorithms, IN : (provider=%v, algOperations=%s, flags=0x%.8X)", p, algOperations.String(), flags)
	defer func() { logger.Infof("EnumAlgorithms, OUT: (provider=%v, algsInfo=%v)", p, algsInfo) }()

	if nCryptEnumAlgorithmsProc == nil {
		err = fmt.Errorf("nCryptEnumAlgorithms() not found in ncrypt.dll")
		return
	}

	r, _, msg := nCryptEnumAlgorithmsProc.Call(
		uintptr(p.handle),
		uintptr(algOperations),
		uintptr(unsafe.Pointer(&algCount)),
		uintptr(unsafe.Pointer(&algListPtr)),
		uintptr(flags),
	)
	if r != 0 {
		if winErr := maybeWinErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("nCryptEnumAlgorithms() returned %X (%v)", r, msg)
		return
	}
	defer func() {
		if algListPtr != nil {
			nCryptFreeBufferProc.Call(uintptr(unsafe.Pointer(algListPtr)))
		}
	}()

	if algCount > 0 {
		algList := (*[1 << 30]ncryptAlgorithmName)(unsafe.Pointer(algListPtr))[:algCount:algCount]
		algsInfo = make([]NcryptAlgorithmInfo, algCount)
		for i := range algsInfo {
			algsInfo[i].fromInternal(algList[i])
		}
	}

	return
}

// IsAlgSupported is a wrapper around NCryptIsAlgSupported.
//
// This function determines if the specified CNG key storage provider
// supports the passed cryptographic algorithm.
func (p *Provider) IsAlgSupported(
	alg NcryptAlgorithm,
	flags NcryptFlag,
) (isSupported bool, ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	logger.Infof("IsAlgSupported, IN : (provider=%v, alg=%s, flags=0x%.8X)", p, alg, flags)
	defer func() { logger.Infof("IsAlgSupported, OUT: (provider=%v, isSupported=%v)", p, isSupported) }()

	if nCryptIsAlgSupportedProc == nil {
		err = fmt.Errorf("nCryptIsAlgSupported() not found in ncrypt.dll")
		return
	}

	utf16Alg, err := stringToUtf16Ptr(string(alg))
	if err != nil {
		err = fmt.Errorf("failed to parse alg \"%s\" (%v)", alg, err)
		return
	}

	r, _, msg := nCryptIsAlgSupportedProc.Call(
		uintptr(p.handle),
		uintptr(unsafe.Pointer(utf16Alg)),
		uintptr(flags),
	)
	if r != 0 {
		if winErr := maybeWinErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("nCryptIsAlgSupported() returned %X (%v)", r, msg)
		return
	}

	isSupported = true

	return
}

// EnumKeys is a wrapper around NCryptEnumKeys.
//
// This function obtains the names of the keys that are stored
// by the specified CNG key storage provider.
func (p *Provider) EnumKeys(
	scope string,
	flags NcryptFlag,
) (keysInfo []NcryptKeyInfo, ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	var keyName *ncryptKeyName
	var enumState unsafe.Pointer

	logger.Infof("EnumKeys, IN : (provider=%v, scope=%s, flags=0x%.8X)", p, scope, flags)
	defer func() { logger.Infof("EnumKeys, OUT: (provider=%v, keysInfo=%v)", p, keysInfo) }()

	if nCryptEnumKeysProc == nil {
		err = fmt.Errorf("nCryptEnumKeys() not found in ncrypt.dll")
		return
	}

	utf16Scope, err := stringToUtf16Ptr(scope)
	if err != nil {
		err = fmt.Errorf("failed to parse scope \"%s\" (%v)", scope, err)
		return
	}

	for {
		r, _, msg := nCryptEnumKeysProc.Call(
			uintptr(p.handle),
			uintptr(unsafe.Pointer(utf16Scope)),
			uintptr(unsafe.Pointer(&keyName)),
			uintptr(unsafe.Pointer(&enumState)),
			uintptr(flags),
		)
		if r == 0x8009002A { // NTE_NO_MORE_ITEMS
			break
		}
		if r != 0 {
			if winErr := maybeWinErr(r); winErr != nil {
				msg = winErr
			}
			keysInfo = nil
			ret = uint64(r)
			err = fmt.Errorf("nCryptEnumKeys() returned %X (%v)", r, msg)
			return
		}
		if keyName != nil {
			var keyInfo NcryptKeyInfo
			keyInfo.fromInternal(*keyName)
			keysInfo = append(keysInfo, keyInfo)
			nCryptFreeBufferProc.Call(uintptr(unsafe.Pointer(keyName)))
		}
	}

	defer func() {
		if enumState != nil {
			nCryptFreeBufferProc.Call(uintptr(enumState))
		}
	}()

	return
}

// OpenKey is a wrapper around NCryptOpenKey.
//
// This function opens a key that exists in the specified
// CNG key storage provider.
func (p *Provider) OpenKey(
	keyName string,
	keySpec NcryptLegacyKeySpec,
	flags NcryptFlag,
) (key Key, ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	var keyAlgBytes []byte
	var keyAlg string
	var tempKey Key
	handle := NcryptKeyHandle(invalidHandleValue)
	key.handle = NcryptKeyHandle(invalidHandleValue)

	logger.Infof("OpenKey, IN : (provider=%v, keyName=%s, keySpec=%s, flags=0x%.8X)", p, keyName, keySpec.String(), flags)
	defer func() { logger.Infof("OpenKey, OUT: (provider=%v, key=%v)", p, key) }()

	if nCryptOpenKeyProc == nil {
		err = fmt.Errorf("nCryptOpenKey() not found in ncrypt.dll")
		return
	}

	utf16KeyName, err := stringToUtf16Ptr(keyName)
	if err != nil {
		err = fmt.Errorf("failed to parse key name \"%s\" (%v)", keyName, err)
		return
	}

	r, _, msg := nCryptOpenKeyProc.Call(
		uintptr(p.handle),
		uintptr(unsafe.Pointer(&handle)),
		uintptr(unsafe.Pointer(utf16KeyName)),
		uintptr(keySpec),
		uintptr(flags),
	)
	if r != 0 {
		if winErr := maybeWinErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("nCryptOpenKey() returned %X (%v)", r, msg)
		return
	}

	tempKey.handle = handle
	tempKey.name = keyName

	keyAlgBytes, ret, err = tempKey.GetProperty(NcryptAlgorithmProperty, NcryptSilentFlag)
	if err != nil {
		logger.Errorf("failed to get key algorithm (%v)", err)
		tempKey.alg = "UNKNOWN"
		err = nil
	} else {
		keyAlg, err = utf16BytesToString(keyAlgBytes)
		if err != nil {
			err = fmt.Errorf("failed to parse key algorithm (%v)", err)
			tempKey.Close()
			return
		}
		tempKey.alg = NcryptAlgorithm(keyAlg)
	}

	key = tempKey

	return
}

// CreatePersistedKey is a wrapper around NCryptCreatePersistedKey,
// NCryptSetProperty and NCryptFinalizeKey.
//
// This function creates a new key and stores it in the specified
// CNG key storage provider. After creating the key, this function
// sets any specified properties, before finalizing the key creation.
func (p *Provider) CreatePersistedKey(
	alg NcryptAlgorithm,
	keyName string,
	keySpec NcryptLegacyKeySpec,
	properties map[NcryptProperty][]byte,
	createKeyFlags NcryptFlag,
	setPropertyFlags NcryptFlag,
	finalizeKeyFlags NcryptFlag,
) (key Key, ret uint64, err error) {
	handle := NcryptKeyHandle(invalidHandleValue)
	key.handle = NcryptKeyHandle(invalidHandleValue)

	defer func() {
		if err != nil {
			logger.Error(err)
			if handle != NcryptKeyHandle(invalidHandleValue) {
				nCryptDeleteKeyProc.Call(uintptr(handle))
			}
		}
	}()

	logger.Infof("CreatePersistedKey, IN : (provider=%v, alg=%s, keyName=%s, keySpec=%s, properties=%v, createKeyFlags=0x%.8X, setPropertyFlags=0x%.8X, finalizeKeyFlags=0x%.8X)",
		p, alg, keyName, keySpec.String(), properties, createKeyFlags, setPropertyFlags, finalizeKeyFlags)
	defer func() { logger.Infof("CreatePersistedKey, OUT: (provider=%v, key=%v)", p, key) }()

	if nCryptCreatePersistedKeyProc == nil {
		err = fmt.Errorf("nCryptCreatePersistedKey() not found in ncrypt.dll")
		return
	}

	if nCryptSetPropertyProc == nil {
		err = fmt.Errorf("nCryptSetProperty() not found in ncrypt.dll")
		return
	}

	if nCryptFinalizeKeyProc == nil {
		err = fmt.Errorf("nCryptFinalizeKey() not found in ncrypt.dll")
		return
	}

	utf16Alg, err := stringToUtf16Ptr(string(alg))
	if err != nil {
		err = fmt.Errorf("failed to parse alg \"%s\" (%v)", string(alg), err)
		return
	}

	utf16KeyName, err := stringToUtf16Ptr(keyName)
	if err != nil {
		err = fmt.Errorf("failed to parse key name \"%s\" (%v)", keyName, err)
		return
	}

	r, _, msg := nCryptCreatePersistedKeyProc.Call(
		uintptr(p.handle),
		uintptr(unsafe.Pointer(&handle)),
		uintptr(unsafe.Pointer(utf16Alg)),
		uintptr(unsafe.Pointer(utf16KeyName)),
		uintptr(keySpec),
		uintptr(createKeyFlags),
	)
	if r != 0 {
		if winErr := maybeWinErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("nCryptCreatePersistedKey() returned %X (%v)", r, msg)
		return
	}

	for propertyName, property := range properties {
		var utf16PropertyName *uint16
		var propertyPtr *byte

		if propertyName == NcryptUiPolicyProperty {
			var internalUiPolicy ncryptUiPolicy
			var uiPolicy NcryptUiPolicy
			err = uiPolicy.deserialize(property)
			if err != nil {
				err = fmt.Errorf("failed to parse property \"%s\" (%v)", propertyName, err)
				return
			}
			internalUiPolicy, err = uiPolicy.toInternal()
			if err != nil {
				err = fmt.Errorf("failed to parse property \"%s\" (%v)", propertyName, err)
				return
			}
			const internalUiPolicySize = int(unsafe.Sizeof(ncryptUiPolicy{}))
			property = (*(*[internalUiPolicySize]byte)(unsafe.Pointer(&internalUiPolicy)))[:]
		}

		utf16PropertyName, err = stringToUtf16Ptr(string(propertyName))
		if err != nil {
			err = fmt.Errorf("failed to parse property \"%s\" (%v)", property, err)
			return
		}

		if len(property) > 0 {
			propertyPtr = &property[0]
		}

		r, _, msg := nCryptSetPropertyProc.Call(
			uintptr(handle),
			uintptr(unsafe.Pointer(utf16PropertyName)),
			uintptr(unsafe.Pointer(propertyPtr)),
			uintptr(len(property)),
			uintptr(setPropertyFlags),
		)
		if r != 0 {
			if winErr := maybeWinErr(r); winErr != nil {
				msg = winErr
			}
			ret = uint64(r)
			err = fmt.Errorf("nCryptSetProperty() 1st call returned %X (%v)", r, msg)
			return
		}
	}

	r, _, msg = nCryptFinalizeKeyProc.Call(
		uintptr(handle),
		uintptr(finalizeKeyFlags),
	)
	if r != 0 {
		if winErr := maybeWinErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("nCryptFinalizeKey() returned %X (%v)", r, msg)
		return
	}

	key.alg = alg
	key.handle = handle
	key.name = keyName

	return
}

// ImportKey is a wrapper around NCryptImportKey.
//
// This function imports a CNG key from a memory BLOB
// into the specified CNG key storage provider.
func (p *Provider) ImportKey(
	importKey Key,
	blobType NcryptKeyBlobType,
	parameterList *NcryptBufferDesc,
	blobData []byte,
	flags NcryptFlag,
) (key Key, ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	var blobDataPtr *byte
	var keyAlgBytes []byte
	var keyAlg string
	var tempKey Key
	handle := NcryptKeyHandle(invalidHandleValue)
	key.handle = NcryptKeyHandle(invalidHandleValue)

	logger.Infof("ImportKey, IN : (provider=%v, importKey=%v, blobType=%s, parameterList=%v, blobData=%v, flags=0x%.8X)",
		p, importKey, blobType, parameterList, blobData, flags)
	defer func() { logger.Infof("ImportKey, OUT: (provider=%v, key=%v)", p, key) }()

	if nCryptImportKeyProc == nil {
		err = fmt.Errorf("nCryptImportKey() not found in ncrypt.dll")
		return
	}

	utf16BlobType, err := stringToUtf16Ptr(string(blobType))
	if err != nil {
		err = fmt.Errorf("failed to parse blob type \"%s\" (%v)", blobType, err)
		return
	}

	if len(blobData) > 0 {
		blobDataPtr = &blobData[0]
	}

	r, _, msg := nCryptImportKeyProc.Call(
		uintptr(p.handle),
		uintptr(importKey.handle),
		uintptr(unsafe.Pointer(utf16BlobType)),
		uintptr(unsafe.Pointer(parameterList)),
		uintptr(unsafe.Pointer(&handle)),
		uintptr(unsafe.Pointer(blobDataPtr)),
		uintptr(len(blobData)),
		uintptr(flags),
	)
	if r != 0 {
		if winErr := maybeWinErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("nCryptImportKey() returned %X (%v)", r, msg)
		return
	}

	tempKey.handle = handle

	keyAlgBytes, ret, err = tempKey.GetProperty(NcryptAlgorithmProperty, NcryptSilentFlag)
	if err != nil {
		err = fmt.Errorf("failed to get key algorithm (%v)", err)
		tempKey.Delete(NcryptSilentFlag)
		return
	}
	keyAlg, err = utf16BytesToString(keyAlgBytes)
	if err != nil {
		err = fmt.Errorf("failed to parse key algorithm (%v)", err)
		tempKey.Delete(NcryptSilentFlag)
		return
	}

	tempKey.alg = NcryptAlgorithm(keyAlg)
	tempKey.name = ""

	key = tempKey

	return
}

// TranslateHandle is a wrapper around NCryptTranslateHandle.
//
// This function translates a CryptoAPI key into a CNG key
// for the specified CNG key storage provider.
func (p *Provider) TranslateHandle(
	legacyProv HcryptProv,
	legacyKey HcryptKey,
	legacyKeySpec NcryptLegacyKeySpec,
	flags NcryptFlag,
) (key Key, ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	var keyAlgBytes []byte
	var keyAlg string
	var keyNameBytes []byte
	var keyName string
	var tempKey Key
	handle := NcryptKeyHandle(invalidHandleValue)
	key.handle = NcryptKeyHandle(invalidHandleValue)

	logger.Infof("TranslateHandle, IN : (provider=%v, legacyProv=%v, legacyKey=%v, legacyKeySpec=%s, flags=0x%.8X)",
		p, legacyProv, legacyKey, legacyKeySpec.String(), flags)
	defer func() { logger.Infof("TranslateHandle, OUT: (provider=%v, key=%v)", p, key) }()

	if nCryptTranslateHandleProc == nil {
		err = fmt.Errorf("nCryptTranslateHandle() not found in ncrypt.dll")
		return
	}

	r, _, msg := nCryptTranslateHandleProc.Call(
		uintptr(p.handle),
		uintptr(unsafe.Pointer(&handle)),
		uintptr(legacyProv),
		uintptr(legacyKey),
		uintptr(legacyKeySpec),
		uintptr(flags),
	)
	if r != 0 {
		if winErr := maybeWinErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("nCryptTranslateHandle() returned %X (%v)", r, msg)
		return
	}

	tempKey.handle = handle

	keyAlgBytes, ret, err = tempKey.GetProperty(NcryptAlgorithmProperty, NcryptSilentFlag)
	if err != nil {
		err = fmt.Errorf("failed to get key algorithm (%v)", err)
		tempKey.Delete(NcryptSilentFlag)
		return
	}
	keyAlg, err = utf16BytesToString(keyAlgBytes)
	if err != nil {
		err = fmt.Errorf("failed to parse key algorithm (%v)", err)
		tempKey.Delete(NcryptSilentFlag)
		return
	}

	keyNameBytes, ret, err = tempKey.GetProperty(NcryptNameProperty, NcryptSilentFlag)
	if err != nil {
		err = fmt.Errorf("failed to get key name (%v)", err)
		tempKey.Delete(NcryptSilentFlag)
		return
	}
	keyName, err = utf16BytesToString(keyNameBytes)
	if err != nil {
		err = fmt.Errorf("failed to parse key name (%v)", err)
		tempKey.Delete(NcryptSilentFlag)
		return
	}

	tempKey.alg = NcryptAlgorithm(keyAlg)
	tempKey.name = keyName

	key = tempKey

	return
}

// Close is a wrapper around NCryptFreeObject for providers.
//
// This function frees a CNG key storage provider.
func (p *Provider) Close() (ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	logger.Infof("Close, IN : (provider=%v)", p)
	defer func() { logger.Infof("Close, OUT: (provider=%v)", p) }()

	if nCryptFreeObjectProc == nil {
		err = fmt.Errorf("nCryptFreeObject() not found in ncrypt.dll")
		return
	}

	r, _, msg := nCryptFreeObjectProc.Call(
		uintptr(p.handle),
	)
	if r != 0 {
		if winErr := maybeWinErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("nCryptFreeObject() returned %X (%v)", r, msg)
		return
	}

	p.handle = NcryptProvHandle(invalidHandleValue)
	p.name = ""

	return
}

// GetProperty is a wrapper around NCryptGetProperty for keys.
//
// This function retrieves the value of a named property for the
// specified CNG key.
func (k *Key) GetProperty(
	propertyName NcryptProperty,
	flags NcryptFlag,
) (property []byte, ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	logger.Infof("GetProperty, IN : (key=%v, propertyName=%s, flags=0x%.8X)", k, propertyName, flags)
	defer func() { logger.Infof("GetProperty, OUT: (key=%v, property=%v)", k, property) }()

	if nCryptGetPropertyProc == nil {
		err = fmt.Errorf("nCryptGetProperty() not found in ncrypt.dll")
		return
	}

	var size uint32

	utf16Property, err := stringToUtf16Ptr(string(propertyName))
	if err != nil {
		err = fmt.Errorf("failed to parse property \"%s\" (%v)", propertyName, err)
		return
	}

	r, _, msg := nCryptGetPropertyProc.Call(
		uintptr(k.handle),
		uintptr(unsafe.Pointer(utf16Property)),
		0,
		0,
		uintptr(unsafe.Pointer(&size)),
		uintptr(flags),
	)
	if r != 0 {
		if winErr := maybeWinErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("nCryptGetProperty() 1st call returned %X (%v)", r, msg)
		return
	}

	if size > 0 {
		property = make([]byte, size)
		r, _, msg = nCryptGetPropertyProc.Call(
			uintptr(k.handle),
			uintptr(unsafe.Pointer(utf16Property)),
			uintptr(unsafe.Pointer(&property[0])),
			uintptr(size),
			uintptr(unsafe.Pointer(&size)),
			uintptr(flags),
		)
		if r != 0 {
			if winErr := maybeWinErr(r); winErr != nil {
				msg = winErr
			}
			property = nil
			ret = uint64(r)
			err = fmt.Errorf("nCryptGetProperty() 2nd call returned %X (%v)", r, msg)
			return
		}

		if size > 0 {
			property = property[:size]
		}
	}

	return
}

// SetProperty is a wrapper around NCryptSetProperty for keys.
//
// This function sets the value for a named property for the
// specified CNG key.
func (k *Key) SetProperty(
	propertyName NcryptProperty,
	property []byte,
	flags NcryptFlag,
) (ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	var propertyPtr *byte

	logger.Infof("SetProperty, IN : (key=%v, propertyName=%s, property=%v, flags=0x%.8X)", k, propertyName, property, flags)
	defer func() { logger.Infof("SetProperty, OUT: (key=%v, propertyName=%s)", k, propertyName) }()

	if nCryptSetPropertyProc == nil {
		err = fmt.Errorf("nCryptSetProperty() not found in ncrypt.dll")
		return
	}

	utf16PropertyName, err := stringToUtf16Ptr(string(propertyName))
	if err != nil {
		err = fmt.Errorf("failed to parse property \"%s\" (%v)", propertyName, err)
		return
	}

	if len(property) > 0 {
		propertyPtr = &property[0]
	}

	r, _, msg := nCryptSetPropertyProc.Call(
		uintptr(k.handle),
		uintptr(unsafe.Pointer(utf16PropertyName)),
		uintptr(unsafe.Pointer(propertyPtr)),
		uintptr(len(property)),
		uintptr(flags),
	)
	if r != 0 {
		if winErr := maybeWinErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("nCryptSetProperty() 1st call returned %X (%v)", r, msg)
		return
	}

	return
}

// Encrypt is a wrapper around NCryptEncrypt.
//
// This function encrypts a block of data using the
// specified CNG key.
func (k *Key) Encrypt(
	input []byte,
	paddingInfo unsafe.Pointer,
	flags NcryptFlag,
) (encryptedData []byte, ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	var size uint32
	var inputPtr *byte

	logger.Infof("Encrypt, IN : (key=%v, input=%v, paddingInfo=%p, flags=0x%.8X)", k, input, paddingInfo, flags)
	defer func() { logger.Infof("Encrypt, OUT: (key=%v, encryptedData=%v)", k, encryptedData) }()

	if nCryptEncryptProc == nil {
		err = fmt.Errorf("nCryptEncrypt() not found in ncrypt.dll")
		return
	}

	if len(input) > 0 {
		inputPtr = &input[0]
	}

	r, _, msg := nCryptEncryptProc.Call(
		uintptr(k.handle),
		uintptr(unsafe.Pointer(inputPtr)),
		uintptr(len(input)),
		uintptr(paddingInfo),
		0,
		0,
		uintptr(unsafe.Pointer(&size)),
		uintptr(flags),
	)
	if r != 0 {
		if winErr := maybeWinErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("nCryptEncrypt() 1st call returned %X (%v)", r, msg)
		return
	}

	if size > 0 {
		encryptedData = make([]byte, size)
		r, _, msg = nCryptEncryptProc.Call(
			uintptr(k.handle),
			uintptr(unsafe.Pointer(inputPtr)),
			uintptr(len(input)),
			uintptr(paddingInfo),
			uintptr(unsafe.Pointer(&encryptedData[0])),
			uintptr(size),
			uintptr(unsafe.Pointer(&size)),
			uintptr(flags),
		)
		if r != 0 {
			if winErr := maybeWinErr(r); winErr != nil {
				msg = winErr
			}
			encryptedData = nil
			ret = uint64(r)
			err = fmt.Errorf("nCryptEncrypt() 2nd call returned %X (%v)", r, msg)
			return
		}

		if size > 0 {
			encryptedData = encryptedData[:size]
		}
	}

	return
}

// Decrypt is a wrapper around NCryptDecrypt.
//
// This function decrypts a block of encrypted data using
// the specified CNG key.
func (k *Key) Decrypt(
	input []byte,
	paddingInfo unsafe.Pointer,
	flags NcryptFlag,
) (decryptedData []byte, ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	var size uint32
	var inputPtr *byte

	logger.Infof("Decrypt, IN : (key=%v, input=%v, paddingInfo=%p, flags=0x%.8X)", k, input, paddingInfo, flags)
	defer func() { logger.Infof("Decrypt, OUT: (key=%v, decryptedData=%v)", k, decryptedData) }()

	if nCryptDecryptProc == nil {
		err = fmt.Errorf("nCryptDecryptProc() not found in ncrypt.dll")
		return
	}

	if len(input) > 0 {
		inputPtr = &input[0]
	}

	r, _, msg := nCryptDecryptProc.Call(
		uintptr(k.handle),
		uintptr(unsafe.Pointer(inputPtr)),
		uintptr(len(input)),
		uintptr(paddingInfo),
		0,
		0,
		uintptr(unsafe.Pointer(&size)),
		uintptr(flags),
	)
	if r != 0 {
		if winErr := maybeWinErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("nCryptDecrypt() 1st call returned %X (%v)", r, msg)
		return
	}

	if size > 0 {
		decryptedData = make([]byte, size)
		r, _, msg = nCryptDecryptProc.Call(
			uintptr(k.handle),
			uintptr(unsafe.Pointer(inputPtr)),
			uintptr(len(input)),
			uintptr(paddingInfo),
			uintptr(unsafe.Pointer(&decryptedData[0])),
			uintptr(size),
			uintptr(unsafe.Pointer(&size)),
			uintptr(flags),
		)
		if r != 0 {
			if winErr := maybeWinErr(r); winErr != nil {
				msg = winErr
			}
			decryptedData = nil
			ret = uint64(r)
			err = fmt.Errorf("nCryptDecrypt() 2nd call returned %X (%v)", r, msg)
			return
		}

		if size > 0 {
			decryptedData = decryptedData[:size]
		}
	}

	return
}

// Export is a wrapper around NCryptExportKey.
//
// This function exports the specified CNG key
// to a memory BLOB.
func (k *Key) Export(
	exportKey Key,
	blobType NcryptKeyBlobType,
	parameterList *NcryptBufferDesc,
	flags NcryptFlag,
) (blobData []byte, ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	var size uint32

	logger.Infof("Export, IN : (key=%v, exportKey=%v, blobType=%s, parameterList=%v, flags=0x%.8X)",
		k, exportKey, blobType, parameterList, flags)
	defer func() { logger.Infof("Export, OUT: (key=%v, blobData=%v)", k, blobData) }()

	if nCryptExportKeyProc == nil {
		err = fmt.Errorf("nCryptExportKey() not found in ncrypt.dll")
		return
	}

	utf16BlobType, err := stringToUtf16Ptr(string(blobType))
	if err != nil {
		err = fmt.Errorf("failed to parse blob type \"%s\" (%v)", blobType, err)
		return
	}

	r, _, msg := nCryptExportKeyProc.Call(
		uintptr(k.handle),
		uintptr(exportKey.handle),
		uintptr(unsafe.Pointer(utf16BlobType)),
		uintptr(unsafe.Pointer(parameterList)),
		0,
		0,
		uintptr(unsafe.Pointer(&size)),
		uintptr(flags),
	)
	if r != 0 {
		if winErr := maybeWinErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("nCryptExportKey() 1st call returned %X (%v)", r, msg)
		return
	}

	if size > 0 {
		blobData = make([]byte, size)
		r, _, msg = nCryptExportKeyProc.Call(
			uintptr(k.handle),
			uintptr(exportKey.handle),
			uintptr(unsafe.Pointer(utf16BlobType)),
			uintptr(unsafe.Pointer(parameterList)),
			uintptr(unsafe.Pointer(&blobData[0])),
			uintptr(size),
			uintptr(unsafe.Pointer(&size)),
			uintptr(flags),
		)
		if r != 0 {
			if winErr := maybeWinErr(r); winErr != nil {
				msg = winErr
			}
			blobData = nil
			ret = uint64(r)
			err = fmt.Errorf("nCryptExportKey() 2nd call returned %X (%v)", r, msg)
			return
		}

		if size > 0 {
			blobData = blobData[:size]
		}
	}

	return
}

// Sign is a wrapper around NCryptSignHash.
//
// This function creates a signature of a hash value
// using the specified CNG key.
func (k *Key) Sign(
	paddingInfo unsafe.Pointer,
	hashValue []byte,
	flags NcryptFlag,
) (signature []byte, ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	var size uint32
	var hashValuePtr *byte

	logger.Infof("Sign, IN : (key=%v, paddingInfo=%p, hashValue=%v, flags=0x%.8X)", k, paddingInfo, hashValue, flags)
	defer func() { logger.Infof("Sign, OUT: (key=%v, signature=%v)", k, signature) }()

	if nCryptSignHashProc == nil {
		err = fmt.Errorf("nCryptSignHash() not found in ncrypt.dll")
		return
	}

	if len(hashValue) > 0 {
		hashValuePtr = &hashValue[0]
	}

	r, _, msg := nCryptSignHashProc.Call(
		uintptr(k.handle),
		uintptr(paddingInfo),
		uintptr(unsafe.Pointer(hashValuePtr)),
		uintptr(len(hashValue)),
		0,
		0,
		uintptr(unsafe.Pointer(&size)),
		uintptr(flags),
	)
	if r != 0 {
		if winErr := maybeWinErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("nCryptSignHash() 1st call returned %X (%v)", r, msg)
		return
	}

	if size > 0 {
		signature = make([]byte, size)
		r, _, msg = nCryptSignHashProc.Call(
			uintptr(k.handle),
			uintptr(paddingInfo),
			uintptr(unsafe.Pointer(hashValuePtr)),
			uintptr(len(hashValue)),
			uintptr(unsafe.Pointer(&signature[0])),
			uintptr(size),
			uintptr(unsafe.Pointer(&size)),
			uintptr(flags),
		)
		if r != 0 {
			if winErr := maybeWinErr(r); winErr != nil {
				msg = winErr
			}
			signature = nil
			ret = uint64(r)
			err = fmt.Errorf("nCryptSignHash() 2nd call returned %X (%v)", r, msg)
			return
		}

		if size > 0 {
			signature = signature[:size]
		}
	}

	return
}

// Verify is a wrapper around NCryptVerifySignature.
//
// This function verifies that the passed signature
// matches the passed hash for the specified CNG key.
func (k *Key) Verify(
	paddingInfo unsafe.Pointer,
	hashValue []byte,
	signature []byte,
	flags NcryptFlag,
) (isVerified bool, ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	var hashValuePtr *byte
	var signaturePtr *byte

	logger.Infof("Verify, IN : (key=%v, paddingInfo=%p, hashValue=%v, signature=%v, flags=0x%.8X)", k, paddingInfo, hashValue, signature, flags)
	defer func() { logger.Infof("Verify, OUT: (key=%v, isVerified=%v)", k, isVerified) }()

	if nCryptVerifySignatureProc == nil {
		err = fmt.Errorf("nCryptVerifySignature() not found in ncrypt.dll")
		return
	}

	if len(hashValue) > 0 {
		hashValuePtr = &hashValue[0]
	}

	if len(signature) > 0 {
		signaturePtr = &signature[0]
	}

	r, _, msg := nCryptVerifySignatureProc.Call(
		uintptr(k.handle),
		uintptr(paddingInfo),
		uintptr(unsafe.Pointer(hashValuePtr)),
		uintptr(len(hashValue)),
		uintptr(unsafe.Pointer(signaturePtr)),
		uintptr(len(signature)),
		uintptr(flags),
	)
	if r != 0 {
		if winErr := maybeWinErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("nCryptVerifySignature() returned %X (%v)", r, msg)
		return
	}

	isVerified = true

	return
}

// Delete is a wrapper around NCryptDeleteKey.
//
// This function deletes the specified CNG key.
func (k *Key) Delete(
	flags NcryptFlag,
) (ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	logger.Infof("Delete, IN : (key=%v, flags=0x%.8X)", k, flags)
	defer func() { logger.Infof("Delete, OUT: (key=%v)", k) }()

	if nCryptDeleteKeyProc == nil {
		err = fmt.Errorf("nCryptDeleteKey() not found in ncrypt.dll")
		return
	}

	r, _, msg := nCryptDeleteKeyProc.Call(
		uintptr(k.handle),
		uintptr(flags),
	)
	if r != 0 {
		if winErr := maybeWinErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("nCryptDeleteKey() returned %X (%v)", r, msg)
		return
	}

	return
}

// SecretAgreement is a wrapper around NCryptSecretAgreement.
//
// This function creates a CNG secret agreement value from
// the specified CNG private key and the passed public key handle.
func (k *Key) SecretAgreement(
	pubKeyHandle NcryptKeyHandle,
	flags NcryptFlag,
) (agreedSecret Secret, ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	handle := NcryptSecretHandle(invalidHandleValue)
	agreedSecret.handle = NcryptSecretHandle(invalidHandleValue)

	logger.Infof("SecretAgreement, IN : (key=%v, pubKeyHandle=0x%.8X, flags=0x%.8X)", k, pubKeyHandle, flags)
	defer func() { logger.Infof("SecretAgreement, OUT: (key=%v, agreedSecret=%v)", k, agreedSecret) }()

	if nCryptSecretAgreementProc == nil {
		err = fmt.Errorf("nCryptSecretAgreement() not found in ncrypt.dll")
		return
	}

	r, _, msg := nCryptSecretAgreementProc.Call(
		uintptr(k.handle),
		uintptr(pubKeyHandle),
		uintptr(unsafe.Pointer(&handle)),
		uintptr(flags),
	)
	if r != 0 {
		if winErr := maybeWinErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("nCryptSecretAgreement() returned %X (%v)", r, msg)
		return
	}

	agreedSecret.handle = handle

	return
}

// Derive is a wrapper around NCryptDeriveKey.
//
// This function derives a key from the specified
// secret agreement value.
// This function is intended to be used as part of a secret
// agreement procedure using persisted secret agreement keys.
// To derive key material by using a persisted secret instead,
// use the KeyDerivation function.
func (s *Secret) Derive(
	kdfType BcryptKdfType,
	parameterList *NcryptBufferDesc,
	flags NcryptFlag,
) (keydata []byte, ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	var size uint32

	logger.Infof("Derive, IN : (secret=%v, kdfType=%s, parameterList=%v, flags=0x%.8X)", s, kdfType, parameterList, flags)
	defer func() { logger.Infof("Derive, OUT: (secret=%v, keydata=%v)", s, keydata) }()

	if nCryptDeriveKeyProc == nil {
		err = fmt.Errorf("nCryptDeriveKey() not found in ncrypt.dll")
		return
	}

	utf16KDF, err := windows.UTF16PtrFromString(string(kdfType))
	if err != nil {
		err = fmt.Errorf("failed to parse kdf type (%v)", err)
		return
	}

	r, _, msg := nCryptDeriveKeyProc.Call(
		uintptr(s.handle),
		uintptr(unsafe.Pointer(utf16KDF)),
		uintptr(unsafe.Pointer(parameterList)),
		0,
		0,
		uintptr(unsafe.Pointer(&size)),
		uintptr(flags),
	)
	if r != 0 {
		if winErr := maybeWinErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("nCryptDeriveKey() 1st call returned %X (%v)", r, msg)
		return
	}

	if size > 0 {
		keydata = make([]byte, size)
		r, _, msg = nCryptDeriveKeyProc.Call(
			uintptr(s.handle),
			uintptr(unsafe.Pointer(utf16KDF)),
			uintptr(unsafe.Pointer(parameterList)),
			uintptr(unsafe.Pointer(&keydata[0])),
			uintptr(size),
			uintptr(unsafe.Pointer(&size)),
			uintptr(flags),
		)
		if r != 0 {
			if winErr := maybeWinErr(r); winErr != nil {
				msg = winErr
			}
			keydata = nil
			ret = uint64(r)
			err = fmt.Errorf("nCryptDeriveKey() 2nd call returned %X (%v)", r, msg)
			return
		}

		if size > 0 {
			keydata = keydata[:size]
		}
	}

	return
}

// KeyDerivation is a wrapper around NCryptKeyDerivation.
//
// This function creates a key from the specified CNG key
// by using the specified key derivation function.
// The function returns the key in a byte array.
func (k *Key) KeyDerivation(
	parameterList *NcryptBufferDesc,
	flags NcryptFlag,
) (keydata []byte, ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	var size uint32

	logger.Infof("KeyDerivation, IN : (key=%v, parameterList=%v, flags=0x%.8X)", k, parameterList, flags)
	defer func() { logger.Infof("KeyDerivation, OUT: (key=%v, keydata=%v)", k, keydata) }()

	if nCryptDeriveKeyProc == nil {
		err = fmt.Errorf("nCryptKeyDerivation() not found in ncrypt.dll")
		return
	}

	r, _, msg := nCryptKeyDerivationProc.Call(
		uintptr(k.handle),
		uintptr(unsafe.Pointer(parameterList)),
		0,
		0,
		uintptr(unsafe.Pointer(&size)),
		uintptr(flags),
	)
	if r != 0 {
		if winErr := maybeWinErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("nCryptKeyDerivation() 1st call returned %X (%v)", r, msg)
		return
	}

	if size > 0 {
		keydata = make([]byte, size)
		r, _, msg = nCryptKeyDerivationProc.Call(
			uintptr(k.handle),
			uintptr(unsafe.Pointer(parameterList)),
			uintptr(unsafe.Pointer(&keydata[0])),
			uintptr(size),
			uintptr(unsafe.Pointer(&size)),
			uintptr(flags),
		)
		if r != 0 {
			if winErr := maybeWinErr(r); winErr != nil {
				msg = winErr
			}
			keydata = nil
			ret = uint64(r)
			err = fmt.Errorf("nCryptKeyDerivation() 2nd call returned %X (%v)", r, msg)
			return
		}

		if size > 0 {
			keydata = keydata[:size]
		}
	}

	return
}

// Close is a wrapper around NCryptFreeObject for keys.
//
// This function frees a CNG key.
func (k *Key) Close() (ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	logger.Infof("Close, IN : (key=%v)", k)
	defer func() { logger.Infof("Close, OUT: (key=%v)", k) }()

	if nCryptFreeObjectProc == nil {
		err = fmt.Errorf("nCryptFreeObject() not found in ncrypt.dll")
		return
	}

	r, _, msg := nCryptFreeObjectProc.Call(
		uintptr(k.handle),
	)
	if r != 0 {
		if winErr := maybeWinErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("nCryptFreeObject() returned %X (%v)", r, msg)
		return
	}

	k.handle = NcryptKeyHandle(invalidHandleValue)
	k.name = ""
	k.alg = ""

	return
}

// CreateClaim / VerifyClaim TODO
