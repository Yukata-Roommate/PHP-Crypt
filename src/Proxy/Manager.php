<?php

namespace YukataRm\Crypt\Proxy;

use YukataRm\Crypt\Interface\EncoderInterface;
use YukataRm\Crypt\Interface\HasherInterface;
use YukataRm\Crypt\Interface\EncrypterInterface;
use YukataRm\Crypt\Interface\PasswordInterface;

use YukataRm\Crypt\Encoder;
use YukataRm\Crypt\Hasher;
use YukataRm\Crypt\Encrypter;
use YukataRm\Crypt\Password;

use YukataRm\Crypt\Enum\EncodeAlgorithmEnum;
use YukataRm\Crypt\Enum\HashAlgorithmEnum;
use YukataRm\Crypt\Enum\EncryptAlgorithmEnum;
use YukataRm\Crypt\Enum\PasswordAlgorithmEnum;

/**
 * Proxy Manager
 * 
 * @package YukataRm\Crypt\Proxy
 */
class Manager
{
    /*----------------------------------------*
     * Encoder
     *----------------------------------------*/

    /**
     * make Encoder instance
     *
     * @param \YukataRm\Crypt\Enum\EncodeAlgorithmEnum|string|null $algorithm
     * @return \YukataRm\Crypt\Interface\EncoderInterface
     */
    public function encoder(EncodeAlgorithmEnum|string|null $algorithm = null): EncoderInterface
    {
        $encoder = new Encoder();

        if (!is_null($algorithm)) $encoder->setAlgorithm($algorithm);

        return $encoder;
    }

    /**
     * make base64 Encoder instance
     * 
     * @return \YukataRm\Crypt\Interface\EncoderInterface
     */
    public function base64Encoder(): EncoderInterface
    {
        return $this->encoder(EncodeAlgorithmEnum::BASE64);
    }

    /**
     * make hex Encoder instance
     * 
     * @return \YukataRm\Crypt\Interface\EncoderInterface
     */
    public function hexEncoder(): EncoderInterface
    {
        return $this->encoder(EncodeAlgorithmEnum::HEX);
    }

    /*----------------------------------------*
     * Encoder - Encode
     *----------------------------------------*/

    /**
     * encode string
     * 
     * @param \YukataRm\Crypt\Enum\EncodeAlgorithmEnum|string $algorithm
     * @param string $data
     * @return string
     */
    public function encode(EncodeAlgorithmEnum|string $algorithm, string $data): string
    {
        return $this->encoder($algorithm)->encode($data);
    }

    /**
     * encode string to base64
     * 
     * @param string $data
     * @return string
     */
    public function base64Encode(string $data): string
    {
        return $this->base64Encoder()->encode($data);
    }

    /**
     * encode string to hex
     * 
     * @param string $data
     * @return string
     */
    public function hexEncode(string $data): string
    {
        return $this->hexEncoder()->encode($data);
    }

    /*----------------------------------------*
     * Encoder - Decode
     *----------------------------------------*/

    /**
     * decode string
     * 
     * @param \YukataRm\Crypt\Enum\EncodeAlgorithmEnum|string $algorithm
     * @param string $data
     * @return string
     */
    public function decode(EncodeAlgorithmEnum|string $algorithm, string $data): string
    {
        return $this->encoder($algorithm)->decode($data);
    }

    /**
     * decode base64 string
     * 
     * @param string $data
     * @return string
     */
    public function base64Decode(string $data): string
    {
        return $this->base64Encoder()->decode($data);
    }

    /**
     * decode hex string
     * 
     * @param string $data
     * @return string
     */
    public function hexDecode(string $data): string
    {
        return $this->hexEncoder()->decode($data);
    }

    /*----------------------------------------*
     * Hasher
     *----------------------------------------*/

    /**
     * make Hasher instance
     * 
     * @param \YukataRm\Crypt\Enum\HashAlgorithmEnum|string|null $algorithm
     * @return \YukataRm\Crypt\Interface\HasherInterface
     */
    public function hasher(HashAlgorithmEnum|string|null $algorithm = null): HasherInterface
    {
        $hasher = new Hasher();

        if (!is_null($algorithm)) $hasher->setAlgorithm($algorithm);

        return $hasher;
    }

    /**
     * make md5 Hasher instance
     * 
     * @return \YukataRm\Crypt\Interface\HasherInterface
     */
    public function md5Hasher(): HasherInterface
    {
        return $this->hasher(HashAlgorithmEnum::MD5);
    }

    /**
     * make sha256 Hasher instance
     * 
     * @return \YukataRm\Crypt\Interface\HasherInterface
     */
    public function sha256Hasher(): HasherInterface
    {
        return $this->hasher(HashAlgorithmEnum::SHA2_256);
    }

    /**
     * make sha512 Hasher instance
     * 
     * @return \YukataRm\Crypt\Interface\HasherInterface
     */
    public function sha512Hasher(): HasherInterface
    {
        return $this->hasher(HashAlgorithmEnum::SHA2_512);
    }

    /**
     * make sha3-256 Hasher instance
     * 
     * @return \YukataRm\Crypt\Interface\HasherInterface
     */
    public function sha3_256Hasher(): HasherInterface
    {
        return $this->hasher(HashAlgorithmEnum::SHA3_256);
    }

    /**
     * make sha3-512 Hasher instance
     * 
     * @return \YukataRm\Crypt\Interface\HasherInterface
     */
    public function sha3_512Hasher(): HasherInterface
    {
        return $this->hasher(HashAlgorithmEnum::SHA3_512);
    }

    /*----------------------------------------*
     * Hasher - Hash
     *----------------------------------------*/

    /**
     * hash string
     * 
     * @param \YukataRm\Crypt\Enum\HashAlgorithmEnum|string $algorithm
     * @param string $data
     * @return string
     */
    public function hash(HashAlgorithmEnum|string $algorithm, string $data): string
    {
        return $this->hasher($algorithm)->hash($data);
    }

    /**
     * hash string with md5
     * 
     * @param string $data
     * @return string
     */
    public function hashMd5(string $data): string
    {
        return $this->md5Hasher()->hash($data);
    }

    /**
     * hash string with sha256
     * 
     * @param string $data
     * @return string
     */
    public function hashSha256(string $data): string
    {
        return $this->sha256Hasher()->hash($data);
    }

    /**
     * hash string with sha512
     * 
     * @param string $data
     * @return string
     */
    public function hashSha512(string $data): string
    {
        return $this->sha512Hasher()->hash($data);
    }

    /**
     * hash string with sha3-256
     * 
     * @param string $data
     * @return string
     */
    public function hashSha3_256(string $data): string
    {
        return $this->sha3_256Hasher()->hash($data);
    }

    /**
     * hash string with sha3-512
     * 
     * @param string $data
     * @return string
     */
    public function hashSha3_512(string $data): string
    {
        return $this->sha3_512Hasher()->hash($data);
    }

    /*----------------------------------------*
     * Encrypter
     *----------------------------------------*/

    /**
     * make Encrypter instance
     * 
     * @param \YukataRm\Crypt\Enum\EncryptAlgorithmEnum|string|null $algorithm
     * @param string|null $key
     * @return \YukataRm\Crypt\Interface\EncrypterInterface
     */
    public function encrypter(EncryptAlgorithmEnum|string|null $algorithm = null, string|null $key = null): EncrypterInterface
    {
        $encrypter = new Encrypter();

        if (!is_null($algorithm)) $encrypter->setAlgorithm($algorithm);
        if (!is_null($key))       $encrypter->setKey($key);

        return $encrypter;
    }

    /**
     * make aes-256-cbc Encrypter instance
     * 
     * @param string|null $key
     * @return \YukataRm\Crypt\Interface\EncrypterInterface
     */
    public function aes256CbcEncrypter(string|null $key = null): EncrypterInterface
    {
        return $this->encrypter(EncryptAlgorithmEnum::AES_256_CBC, $key);
    }

    /**
     * make aes-256-ccm Encrypter instance
     * 
     * @param string|null $key
     * @return \YukataRm\Crypt\Interface\EncrypterInterface
     */
    public function aes256CcmEncrypter(string|null $key = null): EncrypterInterface
    {
        return $this->encrypter(EncryptAlgorithmEnum::AES_256_CCM, $key);
    }

    /**
     * make aes-256-cfb Encrypter instance
     * 
     * @param string|null $key
     * @return \YukataRm\Crypt\Interface\EncrypterInterface
     */
    public function aes256CfbEncrypter(string|null $key = null): EncrypterInterface
    {
        return $this->encrypter(EncryptAlgorithmEnum::AES_256_CFB, $key);
    }

    /**
     * make aes-256-cfb1 Encrypter instance
     * 
     * @param string|null $key
     * @return \YukataRm\Crypt\Interface\EncrypterInterface
     */
    public function aes256Cfb1Encrypter(string|null $key = null): EncrypterInterface
    {
        return $this->encrypter(EncryptAlgorithmEnum::AES_256_CFB1, $key);
    }

    /**
     * make aes-256-cfb8 Encrypter instance
     * 
     * @param string|null $key
     * @return \YukataRm\Crypt\Interface\EncrypterInterface
     */
    public function aes256Cfb8Encrypter(string|null $key = null): EncrypterInterface
    {
        return $this->encrypter(EncryptAlgorithmEnum::AES_256_CFB8, $key);
    }

    /**
     * make aes-256-ctr Encrypter instance
     * 
     * @param string|null $key
     * @return \YukataRm\Crypt\Interface\EncrypterInterface
     */
    public function aes256CtrEncrypter(string|null $key = null): EncrypterInterface
    {
        return $this->encrypter(EncryptAlgorithmEnum::AES_256_CTR, $key);
    }

    /**
     * make aes-256-gcm Encrypter instance
     * 
     * @param string|null $key
     * @return \YukataRm\Crypt\Interface\EncrypterInterface
     */
    public function aes256GcmEncrypter(string|null $key = null): EncrypterInterface
    {
        return $this->encrypter(EncryptAlgorithmEnum::AES_256_GCM, $key);
    }

    /**
     * make aes-256-ocb Encrypter instance
     * 
     * @param string|null $key
     * @return \YukataRm\Crypt\Interface\EncrypterInterface
     */
    public function aes256OcbEncrypter(string|null $key = null): EncrypterInterface
    {
        return $this->encrypter(EncryptAlgorithmEnum::AES_256_OCB, $key);
    }

    /**
     * make aes-256-ofb Encrypter instance
     * 
     * @param string|null $key
     * @return \YukataRm\Crypt\Interface\EncrypterInterface
     */
    public function aes256OfbEncrypter(string|null $key = null): EncrypterInterface
    {
        return $this->encrypter(EncryptAlgorithmEnum::AES_256_OFB, $key);
    }

    /**
     * make aes-256-xts Encrypter instance
     * 
     * @param string|null $key
     * @return \YukataRm\Crypt\Interface\EncrypterInterface
     */
    public function aes256XtsEncrypter(string|null $key = null): EncrypterInterface
    {
        return $this->encrypter(EncryptAlgorithmEnum::AES_256_XTS, $key);
    }

    /*----------------------------------------*
     * Encrypter - Encrypt
     *----------------------------------------*/

    /**
     * encrypt string
     * 
     * @param \YukataRm\Crypt\Enum\EncryptAlgorithmEnum|string $algorithm
     * @param string $key
     * @param string $data
     * @return string
     */
    public function encrypt(EncryptAlgorithmEnum|string $algorithm, string $key, string $data): string
    {
        return $this->encrypter($algorithm, $key)->encrypt($data);
    }

    /**
     * encrypt aes-256-cbc string
     * 
     * @param string $key
     * @param string $data
     * @return string
     */
    public function encryptAes256Cbc(string $key, string $data): string
    {
        return $this->aes256CbcEncrypter($key)->encrypt($data);
    }

    /**
     * encrypt aes-256-ccm string
     * 
     * @param string $key
     * @param string $data
     * @return string
     */
    public function encryptAes256Ccm(string $key, string $data): string
    {
        return $this->aes256CcmEncrypter($key)->encrypt($data);
    }

    /**
     * encrypt aes-256-cfb string
     * 
     * @param string $key
     * @param string $data
     * @return string
     */
    public function encryptAes256Cfb(string $key, string $data): string
    {
        return $this->aes256CfbEncrypter($key)->encrypt($data);
    }

    /**
     * encrypt aes-256-cfb1 string
     * 
     * @param string $key
     * @param string $data
     * @return string
     */
    public function encryptAes256Cfb1(string $key, string $data): string
    {
        return $this->aes256Cfb1Encrypter($key)->encrypt($data);
    }

    /**
     * encrypt aes-256-cfb8 string
     * 
     * @param string $key
     * @param string $data
     * @return string
     */
    public function encryptAes256Cfb8(string $key, string $data): string
    {
        return $this->aes256Cfb8Encrypter($key)->encrypt($data);
    }

    /**
     * encrypt aes-256-ctr string
     * 
     * @param string $key
     * @param string $data
     * @return string
     */
    public function encryptAes256Ctr(string $key, string $data): string
    {
        return $this->aes256CtrEncrypter($key)->encrypt($data);
    }

    /**
     * encrypt aes-256-gcm string
     * 
     * @param string $key
     * @param string $data
     * @return string
     */
    public function encryptAes256Gcm(string $key, string $data): string
    {
        return $this->aes256GcmEncrypter($key)->encrypt($data);
    }

    /**
     * encrypt aes-256-ocb string
     * 
     * @param string $key
     * @param string $data
     * @return string
     */
    public function encryptAes256Ocb(string $key, string $data): string
    {
        return $this->aes256OcbEncrypter($key)->encrypt($data);
    }

    /**
     * encrypt aes-256-ofb string
     * 
     * @param string $key
     * @param string $data
     * @return string
     */
    public function encryptAes256Ofb(string $key, string $data): string
    {
        return $this->aes256OfbEncrypter($key)->encrypt($data);
    }

    /**
     * encrypt aes-256-xts string
     * 
     * @param string $key
     * @param string $data
     * @return string
     */
    public function encryptAes256Xts(string $key, string $data): string
    {
        return $this->aes256XtsEncrypter($key)->encrypt($data);
    }

    /*----------------------------------------*
     * Encrypter - Decrypt
     *----------------------------------------*/

    /**
     * decrypt string
     * 
     * @param \YukataRm\Crypt\Enum\EncryptAlgorithmEnum|string $algorithm
     * @param string $key
     * @param string $data
     * @return string
     */
    public function decrypt(EncryptAlgorithmEnum|string $algorithm, string $key, string $data): string
    {
        return $this->encrypter($algorithm, $key)->decrypt($data);
    }

    /**
     * decrypt aes-256-cbc string
     * 
     * @param string $key
     * @param string $data
     * @return string
     */
    public function decryptAes256Cbc(string $key, string $data): string
    {
        return $this->aes256CbcEncrypter($key)->decrypt($data);
    }

    /**
     * decrypt aes-256-ccm string
     * 
     * @param string $key
     * @param string $data
     * @return string
     */
    public function decryptAes256Ccm(string $key, string $data): string
    {
        return $this->aes256CcmEncrypter($key)->decrypt($data);
    }

    /**
     * decrypt aes-256-cfb string
     * 
     * @param string $key
     * @param string $data
     * @return string
     */
    public function decryptAes256Cfb(string $key, string $data): string
    {
        return $this->aes256CfbEncrypter($key)->decrypt($data);
    }

    /**
     * decrypt aes-256-cfb1 string
     * 
     * @param string $key
     * @param string $data
     * @return string
     */
    public function decryptAes256Cfb1(string $key, string $data): string
    {
        return $this->aes256Cfb1Encrypter($key)->decrypt($data);
    }

    /**
     * decrypt aes-256-cfb8 string
     * 
     * @param string $key
     * @param string $data
     * @return string
     */
    public function decryptAes256Cfb8(string $key, string $data): string
    {
        return $this->aes256Cfb8Encrypter($key)->decrypt($data);
    }

    /**
     * decrypt aes-256-ctr string
     * 
     * @param string $key
     * @param string $data
     * @return string
     */
    public function decryptAes256Ctr(string $key, string $data): string
    {
        return $this->aes256CtrEncrypter($key)->decrypt($data);
    }

    /**
     * decrypt aes-256-gcm string
     * 
     * @param string $key
     * @param string $data
     * @return string
     */
    public function decryptAes256Gcm(string $key, string $data): string
    {
        return $this->aes256GcmEncrypter($key)->decrypt($data);
    }

    /**
     * decrypt aes-256-ocb string
     * 
     * @param string $key
     * @param string $data
     * @return string
     */
    public function decryptAes256Ocb(string $key, string $data): string
    {
        return $this->aes256OcbEncrypter($key)->decrypt($data);
    }

    /**
     * decrypt aes-256-ofb string
     * 
     * @param string $key
     * @param string $data
     * @return string
     */
    public function decryptAes256Ofb(string $key, string $data): string
    {
        return $this->aes256OfbEncrypter($key)->decrypt($data);
    }

    /**
     * decrypt aes-256-xts string
     * 
     * @param string $key
     * @param string $data
     * @return string
     */
    public function decryptAes256Xts(string $key, string $data): string
    {
        return $this->aes256XtsEncrypter($key)->decrypt($data);
    }

    /*----------------------------------------*
     * Password
     *----------------------------------------*/

    /**
     * make Password instance
     * 
     * @param \YukataRm\Crypt\Enum\PasswordAlgorithmEnum|string|null $algorithm
     * @return \YukataRm\Crypt\Interface\PasswordInterface
     */
    public function password(PasswordAlgorithmEnum|string|null $algorithm = null): PasswordInterface
    {
        $password = new Password();

        if (!is_null($algorithm)) $password->setAlgorithm($algorithm);

        return $password;
    }

    /**
     * make default Password instance
     * 
     * @return \YukataRm\Crypt\Interface\PasswordInterface
     */
    public function passwordDefault(): PasswordInterface
    {
        return $this->password(PasswordAlgorithmEnum::DEFAULT);
    }

    /**
     * make bcrypt Password instance
     * 
     * @param string|null $salt
     * @param int|null $cost
     * @return \YukataRm\Crypt\Interface\PasswordInterface
     */
    public function passwordBcrypt(string|null $salt = null, int|null $cost = null): PasswordInterface
    {
        $password = $this->password(PasswordAlgorithmEnum::BCRYPT);

        if (is_string($salt)) $password->addSalt($salt);
        if (is_int($cost))    $password->addCost($cost);

        return $password;
    }

    /**
     * make argon2i Password instance
     * 
     * @param int|null $memoryCost
     * @param int|null $timeCost
     * @param int|null $threads
     * @return \YukataRm\Crypt\Interface\PasswordInterface
     */
    public function passwordArgon2i(
        int|null $memoryCost = null,
        int|null $timeCost = null,
        int|null $threads = null
    ): PasswordInterface {
        $password = $this->password(PasswordAlgorithmEnum::ARGON2I);

        if (is_int($memoryCost)) $password->addMemoryCost($memoryCost);
        if (is_int($timeCost))   $password->addTimeCost($timeCost);
        if (is_int($threads))    $password->addThreads($threads);

        return $password;
    }

    /**
     * make argon2id Password instance
     * 
     * @param int|null $memoryCost
     * @param int|null $timeCost
     * @param int|null $threads
     * @return \YukataRm\Crypt\Interface\PasswordInterface
     */
    public function passwordArgon2id(
        int|null $memoryCost = null,
        int|null $timeCost = null,
        int|null $threads = null
    ): PasswordInterface {
        $password = $this->password(PasswordAlgorithmEnum::ARGON2ID);

        if (is_int($memoryCost)) $password->addMemoryCost($memoryCost);
        if (is_int($timeCost))   $password->addTimeCost($timeCost);
        if (is_int($threads))    $password->addThreads($threads);

        return $password;
    }

    /*----------------------------------------*
     * Password - generate
     *----------------------------------------*/

    /**
     * generate password
     * 
     * @param string $characters
     * @param int $length
     * @return string
     */
    public function generatePassword(string $characters, int $length): string
    {
        return $this->password()->generate($characters, $length);
    }

    /**
     * generate password by
     * 
     * @param int $length
     * @param bool $useAlphabet
     * @param bool $useNumeric
     * @param bool $useSymbol
     * @param string|null $addCharacters
     * @return string
     */
    public function generatePasswordBy(
        int $length,
        bool $useAlphabet = true,
        bool $useNumeric = true,
        bool $useSymbol = true,
        string|null $addCharacters = null
    ): string {
        return $this->password()->generateBy($length, $useAlphabet, $useNumeric, $useSymbol, $addCharacters);
    }

    /*----------------------------------------*
     * Password - hash
     *----------------------------------------*/

    /**
     * make hash password
     * 
     * @param \YukataRm\Crypt\Enum\PasswordAlgorithmEnum|string $algorithm
     * @param string $data
     * @return string
     */
    public function hashPassword(
        PasswordAlgorithmEnum|string $algorithm,
        string $data
    ): string {
        return $this->password($algorithm)->hash($data);
    }

    /**
     * make hash password with default algorithm
     * 
     * @param string $data
     * @return string
     */
    public function hashPasswordDefault(string $data): string
    {
        return $this->passwordDefault()->hash($data);
    }

    /**
     * make hash password with bcrypt algorithm
     * 
     * @param string $data
     * @param string|null $salt
     * @param int|null $cost
     * @return string
     */
    public function hashPasswordBcrypt(string $data, string|null $salt = null, int|null $cost = null): string
    {
        return $this->passwordBcrypt($salt, $cost)->hash($data);
    }

    /**
     * make hash password with argon2i algorithm
     * 
     * @param string $data
     * @param int|null $memoryCost
     * @param int|null $timeCost
     * @param int|null $threads
     * @return string
     */
    public function hashPasswordArgon2i(
        string $data,
        int|null $memoryCost = null,
        int|null $timeCost = null,
        int|null $threads = null
    ): string {
        return $this->passwordArgon2i($memoryCost, $timeCost, $threads)->hash($data);
    }

    /**
     * make hash password with argon2id algorithm
     * 
     * @param string $data
     * @param int|null $memoryCost
     * @param int|null $timeCost
     * @param int|null $threads
     * @return string
     */
    public function hashPasswordArgon2id(
        string $data,
        int|null $memoryCost = null,
        int|null $timeCost = null,
        int|null $threads = null
    ): string {
        return $this->passwordArgon2id($memoryCost, $timeCost, $threads)->hash($data);
    }

    /*----------------------------------------*
     * Password - Verify
     *----------------------------------------*/

    /**
     * verify password
     * 
     * @param string $data
     * @param string $hash
     * @return bool
     */
    public function verifyPassword(string $data, string $hash): bool
    {
        return $this->password()->verify($data, $hash);
    }

    /*----------------------------------------*
     * Password - Need Rehash
     *----------------------------------------*/

    /**
     * check password need rehash
     * 
     * @param \YukataRm\Crypt\Enum\PasswordAlgorithmEnum|string $algorithm
     * @param string $hash
     * @return bool
     */
    public function isPasswordNeedRehash(
        PasswordAlgorithmEnum|string $algorithm,
        string $hash
    ): bool {
        return $this->password($algorithm)->needsRehash($hash);
    }

    /**
     * check password need rehash with default algorithm
     * 
     * @param string $hash
     * @return bool
     */
    public function isPasswordNeedRehashDefault(string $hash): bool
    {
        return $this->passwordDefault()->needsRehash($hash);
    }

    /**
     * check password need rehash with bcrypt algorithm
     * 
     * @param string $hash
     * @param string|null $salt
     * @param int|null $cost
     * @return bool
     */
    public function isPasswordNeedRehashBcrypt(string $hash, string|null $salt = null, int|null $cost = null): bool
    {
        return $this->passwordBcrypt($salt, $cost)->needsRehash($hash);
    }

    /**
     * check password need rehash with argon2i algorithm
     * 
     * @param string $hash
     * @param int|null $memoryCost
     * @param int|null $timeCost
     * @param int|null $threads
     * @return bool
     */
    public function isPasswordNeedRehashArgon2i(
        string $hash,
        int|null $memoryCost = null,
        int|null $timeCost = null,
        int|null $threads = null
    ): bool {
        return $this->passwordArgon2i($memoryCost, $timeCost, $threads)->needsRehash($hash);
    }

    /**
     * check password need rehash with argon2id algorithm
     * 
     * @param string $hash
     * @param int|null $memoryCost
     * @param int|null $timeCost
     * @param int|null $threads
     * @return bool
     */
    public function isPasswordNeedRehashArgon2id(
        string $hash,
        int|null $memoryCost = null,
        int|null $timeCost = null,
        int|null $threads = null
    ): bool {
        return $this->passwordArgon2id($memoryCost, $timeCost, $threads)->needsRehash($hash);
    }

    /*----------------------------------------*
     * Password - Rehash
     *----------------------------------------*/

    /**
     * rehash password if needed
     * 
     * @param \YukataRm\Crypt\Enum\PasswordAlgorithmEnum|string $algorithm
     * @param string $hash
     * @return string
     */
    public function rehashPassword(
        PasswordAlgorithmEnum|string $algorithm,
        string $hash
    ): string {
        return $this->password($algorithm)->rehashIfNeeded($hash);
    }

    /**
     * rehash password if needed with default algorithm
     * 
     * @param string $hash
     * @return string
     */
    public function rehashPasswordDefault(string $hash): string
    {
        return $this->passwordDefault()->rehashIfNeeded($hash);
    }

    /**
     * rehash password if needed with bcrypt algorithm
     * 
     * @param string $hash
     * @param string|null $salt
     * @param int|null $cost
     * @return string
     */
    public function rehashPasswordBcrypt(string $hash, string|null $salt = null, int|null $cost = null): string
    {
        return $this->passwordBcrypt($salt, $cost)->rehashIfNeeded($hash);
    }

    /**
     * rehash password if needed with argon2i algorithm
     * 
     * @param string $hash
     * @param int|null $memoryCost
     * @param int|null $timeCost
     * @param int|null $threads
     * @return string
     */
    public function rehashPasswordArgon2i(
        string $hash,
        int|null $memoryCost = null,
        int|null $timeCost = null,
        int|null $threads = null
    ): string {
        return $this->passwordArgon2i($memoryCost, $timeCost, $threads)->rehashIfNeeded($hash);
    }

    /**
     * rehash password if needed with argon2id algorithm
     * 
     * @param string $hash
     * @param int|null $memoryCost
     * @param int|null $timeCost
     * @param int|null $threads
     * @return string
     */
    public function rehashPasswordArgon2id(
        string $hash,
        int|null $memoryCost = null,
        int|null $timeCost = null,
        int|null $threads = null
    ): string {
        return $this->passwordArgon2id($memoryCost, $timeCost, $threads)->rehashIfNeeded($hash);
    }
}
