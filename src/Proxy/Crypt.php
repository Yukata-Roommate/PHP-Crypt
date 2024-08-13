<?php

namespace YukataRm\Crypt\Proxy;

use YukataRm\StaticProxy\StaticProxy;

use YukataRm\Crypt\Proxy\Manager;

/**
 * Crypt Proxy
 * 
 * @package YukataRm\Crypt\Proxy
 * 
 * @method static \YukataRm\Crypt\Interface\EncoderInterface encoder(\YukataRm\Crypt\Enum\EncodeAlgorithmEnum|string|null $algorithm = null)
 * @method static \YukataRm\Crypt\Interface\EncoderInterface base64Encoder()
 * @method static \YukataRm\Crypt\Interface\EncoderInterface hexEncoder()
 * 
 * @method static string encode(\YukataRm\Crypt\Enum\EncodeAlgorithmEnum|string $algorithm, string $data)
 * @method static string base64Encode(string $data)
 * @method static string hexEncode(string $data)
 * 
 * @method static string decode(\YukataRm\Crypt\Enum\EncodeAlgorithmEnum|string $algorithm, string $data)
 * @method static string base64Decode(string $data)
 * @method static string hexDecode(string $data)
 * 
 * 
 * @method static \YukataRm\Crypt\Interface\HasherInterface hasher(\YukataRm\Crypt\Enum\HashAlgorithmEnum|string|null $algorithm = null)
 * @method static \YukataRm\Crypt\Interface\HasherInterface md5Hasher()
 * @method static \YukataRm\Crypt\Interface\HasherInterface sha256Hasher()
 * @method static \YukataRm\Crypt\Interface\HasherInterface sha512Hasher()
 * @method static \YukataRm\Crypt\Interface\HasherInterface sha3_256Hasher()
 * @method static \YukataRm\Crypt\Interface\HasherInterface sha3_512Hasher()
 * 
 * @method static string hash(\YukataRm\Crypt\Enum\HashAlgorithmEnum|string $algorithm, string $data)
 * @method static string hashMd5(string $data)
 * @method static string hashSha256(string $data)
 * @method static string hashSha512(string $data)
 * @method static string hashSha3_256(string $data)
 * @method static string hashSha3_512(string $data)
 * 
 * 
 * @method static \YukataRm\Crypt\Interface\EncrypterInterface encrypter(\YukataRm\Crypt\Enum\EncryptAlgorithmEnum|string|null $algorithm = null, string|null $key = null)
 * @method static \YukataRm\Crypt\Interface\EncrypterInterface aes256CbcEncrypter(string|null $key = null)
 * @method static \YukataRm\Crypt\Interface\EncrypterInterface aes256CcmEncrypter(string|null $key = null)
 * @method static \YukataRm\Crypt\Interface\EncrypterInterface aes256CfbEncrypter(string|null $key = null)
 * @method static \YukataRm\Crypt\Interface\EncrypterInterface aes256Cfb1Encrypter(string|null $key = null)
 * @method static \YukataRm\Crypt\Interface\EncrypterInterface aes256Cfb8Encrypter(string|null $key = null)
 * @method static \YukataRm\Crypt\Interface\EncrypterInterface aes256CtrEncrypter(string|null $key = null)
 * @method static \YukataRm\Crypt\Interface\EncrypterInterface aes256GcmEncrypter(string|null $key = null)
 * @method static \YukataRm\Crypt\Interface\EncrypterInterface aes256OcbEncrypter(string|null $key = null)
 * @method static \YukataRm\Crypt\Interface\EncrypterInterface aes256OfbEncrypter(string|null $key = null)
 * @method static \YukataRm\Crypt\Interface\EncrypterInterface aes256XtsEncrypter(string|null $key = null)
 * 
 * @method static string encrypt(\YukataRm\Crypt\Enum\EncryptAlgorithmEnum|string $algorithm, string $key, string $data)
 * @method static string encryptAes256Cbc(string $key, string $data)
 * @method static string encryptAes256Ccm(string $key, string $data)
 * @method static string encryptAes256Cfb(string $key, string $data)
 * @method static string encryptAes256Cfb1(string $key, string $data)
 * @method static string encryptAes256Cfb8(string $key, string $data)
 * @method static string encryptAes256Ctr(string $key, string $data)
 * @method static string encryptAes256Gcm(string $key, string $data)
 * @method static string encryptAes256Ocb(string $key, string $data)
 * @method static string encryptAes256Ofb(string $key, string $data)
 * @method static string encryptAes256Xts(string $key, string $data)
 * 
 * @method static string decrypt(\YukataRm\Crypt\Enum\EncryptAlgorithmEnum|string $algorithm, string $key, string $data)
 * @method static string decryptAes256Cbc(string $key, string $data)
 * @method static string decryptAes256Ccm(string $key, string $data)
 * @method static string decryptAes256Cfb(string $key, string $data)
 * @method static string decryptAes256Cfb1(string $key, string $data)
 * @method static string decryptAes256Cfb8(string $key, string $data)
 * @method static string decryptAes256Ctr(string $key, string $data)
 * @method static string decryptAes256Gcm(string $key, string $data)
 * @method static string decryptAes256Ocb(string $key, string $data)
 * @method static string decryptAes256Ofb(string $key, string $data)
 * @method static string decryptAes256Xts(string $key, string $data)
 * 
 * 
 * @method static \YukataRm\Crypt\Interface\PasswordInterface password(\YukataRm\Crypt\Enum\PasswordAlgorithmEnum|string|null $algorithm = null)
 * @method static \YukataRm\Crypt\Interface\PasswordInterface passwordDefault()
 * @method static \YukataRm\Crypt\Interface\PasswordInterface passwordBcrypt(string|null $salt = null, int|null $cost = null)
 * @method static \YukataRm\Crypt\Interface\PasswordInterface passwordArgon2i(int|null $memoryCost = null, int|null $timeCost = null, int|null $threads = null)
 * @method static \YukataRm\Crypt\Interface\PasswordInterface passwordArgon2id(int|null $memoryCost = null, int|null $timeCost = null, int|null $threads = null)
 * 
 * @method static string generatePassword(string $characters, int $length)
 * @method static string generatePasswordBy(int $length, bool $useAlphabet = true, bool $useNumeric = true, bool $useSymbol = true, string|null $addCharacters = null)
 * 
 * @method static string hashPassword(\YukataRm\Crypt\Enum\PasswordAlgorithmEnum|string $algorithm, string $data)
 * @method static string hashPasswordDefault(string $data)
 * @method static string hashPasswordBcrypt(string $data, string|null $salt = null, int|null $cost = null)
 * @method static string hashPasswordArgon2i(string $data, int|null $memoryCost = null, int|null $timeCost = null, int|null $threads = null)
 * @method static string hashPasswordArgon2id(string $data, int|null $memoryCost = null, int|null $timeCost = null, int|null $threads = null)
 * 
 * @method static bool verifyPassword(string $data, string $hash)
 * 
 * @method static bool isPasswordNeedRehash(\YukataRm\Crypt\Enum\PasswordAlgorithmEnum|string $algorithm, string $hash)
 * @method static bool isPasswordNeedRehashDefault(string $hash)
 * @method static bool isPasswordNeedRehashBcrypt(string $hash, string|null $salt = null, int|null $cost = null)
 * @method static bool isPasswordNeedRehashArgon2i(string $hash, int|null $memoryCost = null, int|null $timeCost = null, int|null $threads = null)
 * @method static bool isPasswordNeedRehashArgon2id(string $hash, int|null $memoryCost = null, int|null $timeCost = null, int|null $threads = null)
 * 
 * @method static string rehashPassword(\YukataRm\Crypt\Enum\PasswordAlgorithmEnum|string $algorithm, string $hash)
 * @method static string rehashPasswordDefault(string $hash)
 * @method static string rehashPasswordBcrypt(string $hash, string|null $salt = null, int|null $cost = null)
 * @method static string rehashPasswordArgon2i(string $hash, int|null $memoryCost = null, int|null $timeCost = null, int|null $threads = null)
 * @method static string rehashPasswordArgon2id(string $hash, int|null $memoryCost = null, int|null $timeCost = null, int|null $threads = null)
 * 
 * @see \YukataRm\Crypt\Proxy\Manager
 */
class Crypt extends StaticProxy
{
    /** 
     * get class name calling dynamic method
     * 
     * @return string 
     */
    protected static function getCallableClassName(): string
    {
        return Manager::class;
    }
}
