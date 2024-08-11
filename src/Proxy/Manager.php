<?php

namespace YukataRm\Crypt\Proxy;

use YukataRm\Crypt\Interface\EncoderInterface;
use YukataRm\Crypt\Interface\HasherInterface;
use YukataRm\Crypt\Interface\EncrypterInterface;

use YukataRm\Crypt\Encoder;
use YukataRm\Crypt\Hasher;
use YukataRm\Crypt\Encrypter;

use YukataRm\Crypt\Enum\EncodeAlgorithmEnum;
use YukataRm\Crypt\Enum\HashAlgorithmEnum;
use YukataRm\Crypt\Enum\EncryptAlgorithmEnum;

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
     * @return \YukataRm\Crypt\Interface\EncoderInterface
     */
    public function encoder(): EncoderInterface
    {
        return new Encoder();
    }

    /*----------------------------------------*
     * Encoder - Encode
     *----------------------------------------*/

    /**
     * encode string
     * 
     * @param \YukataRm\Crypt\Enum\EncodeAlgorithmEnum $algorithm
     * @param string $data
     * @return string
     */
    protected function encode(EncodeAlgorithmEnum $algorithm, string $data): string
    {
        return $this->encoder()->setAlgorithm($algorithm)->encode($data);
    }

    /**
     * encode string to base64
     * 
     * @param string $data
     * @return string
     */
    public function base64Encode(string $data): string
    {
        return $this->encode(EncodeAlgorithmEnum::BASE64, $data);
    }

    /**
     * encode string to hex
     * 
     * @param string $data
     * @return string
     */
    public function hexEncode(string $data): string
    {
        return $this->encode(EncodeAlgorithmEnum::HEX, $data);
    }

    /*----------------------------------------*
     * Encoder - Decode
     *----------------------------------------*/

    /**
     * decode string
     * 
     * @param \YukataRm\Crypt\Enum\EncodeAlgorithmEnum $algorithm
     * @param string $data
     * @return string
     */
    protected function decode(EncodeAlgorithmEnum $algorithm, string $data): string
    {
        return $this->encoder()->setAlgorithm($algorithm)->decode($data);
    }

    /**
     * decode base64 string
     * 
     * @param string $data
     * @return string
     */
    public function base64Decode(string $data): string
    {
        return $this->decode(EncodeAlgorithmEnum::BASE64, $data);
    }

    /**
     * decode hex string
     * 
     * @param string $data
     * @return string
     */
    public function hexDecode(string $data): string
    {
        return $this->decode(EncodeAlgorithmEnum::HEX, $data);
    }

    /*----------------------------------------*
     * Hasher
     *----------------------------------------*/

    /**
     * make Hasher instance
     * 
     * @return \YukataRm\Crypt\Interface\HasherInterface
     */
    public function hasher(): HasherInterface
    {
        return new Hasher();
    }

    /*----------------------------------------*
     * Hasher - Hash
     *----------------------------------------*/

    /**
     * hash string
     * 
     * @param \YukataRm\Crypt\Enum\HashAlgorithmEnum $algorithm
     * @param string $data
     * @return string
     */
    protected function hash(HashAlgorithmEnum $algorithm, string $data): string
    {
        return $this->hasher()->setAlgorithm($algorithm)->hash($data);
    }

    /**
     * hash string with md5
     * 
     * @param string $data
     * @return string
     */
    public function hashMd5(string $data): string
    {
        return $this->hash(HashAlgorithmEnum::MD5, $data);
    }

    /**
     * hash string with sha256
     * 
     * @param string $data
     * @return string
     */
    public function hashSha256(string $data): string
    {
        return $this->hash(HashAlgorithmEnum::SHA2_256, $data);
    }

    /**
     * hash string with sha512
     * 
     * @param string $data
     * @return string
     */
    public function hashSha512(string $data): string
    {
        return $this->hash(HashAlgorithmEnum::SHA2_512, $data);
    }

    /**
     * hash string with sha3-256
     * 
     * @param string $data
     * @return string
     */
    public function hashSha3_256(string $data): string
    {
        return $this->hash(HashAlgorithmEnum::SHA3_256, $data);
    }

    /**
     * hash string with sha3-512
     * 
     * @param string $data
     * @return string
     */
    public function hashSha3_512(string $data): string
    {
        return $this->hash(HashAlgorithmEnum::SHA3_512, $data);
    }

    /*----------------------------------------*
     * Encrypter
     *----------------------------------------*/

    /**
     * make Encrypter instance
     * 
     * @return \YukataRm\Crypt\Interface\EncrypterInterface
     */
    public function encrypter(): EncrypterInterface
    {
        return new Encrypter();
    }

    /*----------------------------------------*
     * Encrypter - Encrypt
     *----------------------------------------*/

    /**
     * encrypt string
     * 
     * @param \YukataRm\Crypt\Enum\EncryptAlgorithmEnum $algorithm
     * @param string $key
     * @param string $data
     * @return string
     */
    protected function encrypt(EncryptAlgorithmEnum $algorithm, string $key, string $data): string
    {
        return $this->encrypter()->setAlgorithm($algorithm)->setKey($key)->encrypt($data);
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
        return $this->encrypt(EncryptAlgorithmEnum::AES_256_CBC, $key, $data);
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
        return $this->encrypt(EncryptAlgorithmEnum::AES_256_CCM, $key, $data);
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
        return $this->encrypt(EncryptAlgorithmEnum::AES_256_CFB, $key, $data);
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
        return $this->encrypt(EncryptAlgorithmEnum::AES_256_CFB1, $key, $data);
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
        return $this->encrypt(EncryptAlgorithmEnum::AES_256_CFB8, $key, $data);
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
        return $this->encrypt(EncryptAlgorithmEnum::AES_256_CTR, $key, $data);
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
        return $this->encrypt(EncryptAlgorithmEnum::AES_256_GCM, $key, $data);
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
        return $this->encrypt(EncryptAlgorithmEnum::AES_256_OCB, $key, $data);
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
        return $this->encrypt(EncryptAlgorithmEnum::AES_256_OFB, $key, $data);
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
        return $this->encrypt(EncryptAlgorithmEnum::AES_256_XTS, $key, $data);
    }

    /*----------------------------------------*
     * Encrypter - Decrypt
     *----------------------------------------*/

    /**
     * decrypt string
     * 
     * @param \YukataRm\Crypt\Enum\EncryptAlgorithmEnum $algorithm
     * @param string $key
     * @param string $data
     * @return string
     */
    protected function decrypt(EncryptAlgorithmEnum $algorithm, string $key, string $data): string
    {
        return $this->encrypter()->setAlgorithm($algorithm)->setKey($key)->decrypt($data);
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
        return $this->decrypt(EncryptAlgorithmEnum::AES_256_CBC, $key, $data);
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
        return $this->decrypt(EncryptAlgorithmEnum::AES_256_CCM, $key, $data);
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
        return $this->decrypt(EncryptAlgorithmEnum::AES_256_CFB, $key, $data);
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
        return $this->decrypt(EncryptAlgorithmEnum::AES_256_CFB1, $key, $data);
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
        return $this->decrypt(EncryptAlgorithmEnum::AES_256_CFB8, $key, $data);
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
        return $this->decrypt(EncryptAlgorithmEnum::AES_256_CTR, $key, $data);
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
        return $this->decrypt(EncryptAlgorithmEnum::AES_256_GCM, $key, $data);
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
        return $this->decrypt(EncryptAlgorithmEnum::AES_256_OCB, $key, $data);
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
        return $this->decrypt(EncryptAlgorithmEnum::AES_256_OFB, $key, $data);
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
        return $this->decrypt(EncryptAlgorithmEnum::AES_256_XTS, $key, $data);
    }
}
