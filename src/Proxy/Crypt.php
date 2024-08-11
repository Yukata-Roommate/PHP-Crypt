<?php

namespace YukataRm\Crypt\Proxy;

use YukataRm\StaticProxy\StaticProxy;

use YukataRm\Crypt\Proxy\Manager;

/**
 * Crypt Proxy
 * 
 * @package YukataRm\Crypt\Proxy
 * 
 * @method static \YukataRm\Crypt\Interface\EncoderInterface encoder()
 * @method static string base64Encode(string $data)
 * @method static string hexEncode(string $data)
 * @method static string base64Decode(string $data)
 * @method static string hexDecode(string $data)
 * 
 * @method static \YukataRm\Crypt\Interface\HasherInterface hasher()
 * @method static string hashMd5(string $data)
 * @method static string hashSha256(string $data)
 * @method static string hashSha512(string $data)
 * @method static string hashSha3_256(string $data)
 * @method static string hashSha3_512(string $data)
 * 
 * @method static \YukataRm\Crypt\Interface\EncrypterInterface encrypter()
 * @method static string encryptAes256Cbc(string $data, string $key)
 * @method static string encryptAes256Ccm(string $data, string $key)
 * @method static string encryptAes256Cfb(string $data, string $key)
 * @method static string encryptAes256Cfb1(string $data, string $key)
 * @method static string encryptAes256Cfb8(string $data, string $key)
 * @method static string encryptAes256Ctr(string $data, string $key)
 * @method static string encryptAes256Gcm(string $data, string $key)
 * @method static string encryptAes256Ocb(string $data, string $key)
 * @method static string encryptAes256Ofb(string $data, string $key)
 * @method static string encryptAes256Xts(string $data, string $key)
 * @method static string decryptAes256Cbc(string $data, string $key)
 * @method static string decryptAes256Ccm(string $data, string $key)
 * @method static string decryptAes256Cfb(string $data, string $key)
 * @method static string decryptAes256Cfb1(string $data, string $key)
 * @method static string decryptAes256Cfb8(string $data, string $key)
 * @method static string decryptAes256Ctr(string $data, string $key)
 * @method static string decryptAes256Gcm(string $data, string $key)
 * @method static string decryptAes256Ocb(string $data, string $key)
 * @method static string decryptAes256Ofb(string $data, string $key)
 * @method static string decryptAes256Xts(string $data, string $key)
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
