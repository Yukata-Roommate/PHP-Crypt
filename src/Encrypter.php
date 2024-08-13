<?php

namespace YukataRm\Crypt;

use YukataRm\Crypt\Interface\EncrypterInterface;

use YukataRm\Crypt\Enum\EncryptAlgorithmEnum;
use YukataRm\Crypt\Proxy\Crypt;

/**
 * Encrypter
 * 
 * @package YukataRm\Crypt
 */
class Encrypter implements EncrypterInterface
{
    /*----------------------------------------*
     * Algorithm
     *----------------------------------------*/

    /**
     * algorithm
     * 
     * @var \YukataRm\Crypt\Enum\EncryptAlgorithmEnum|null
     */
    protected EncryptAlgorithmEnum|null $algorithm = null;

    /**
     * get algorithm
     * 
     * @return \YukataRm\Crypt\Enum\EncryptAlgorithmEnum|null
     */
    public function algorithm(): EncryptAlgorithmEnum|null
    {
        return $this->algorithm;
    }

    /**
     * set algorithm
     * 
     * @param \YukataRm\Crypt\Enum\EncryptAlgorithmEnum|string $algorithm
     * @return static
     */
    public function setAlgorithm(EncryptAlgorithmEnum|string $algorithm): static
    {
        if (is_string($algorithm)) $algorithm = EncryptAlgorithmEnum::tryFrom($algorithm);

        $this->algorithm = $algorithm;

        return $this;
    }

    /**
     * set algorithm to aes-256-cbc
     * 
     * @return static
     */
    public function useAes256Cbc(): static
    {
        return $this->setAlgorithm(EncryptAlgorithmEnum::AES_256_CBC);
    }

    /**
     * set algorithm to aes-256-ccm
     * 
     * @return static
     */
    public function useAes256Ccm(): static
    {
        return $this->setAlgorithm(EncryptAlgorithmEnum::AES_256_CCM);
    }

    /**
     * set algorithm to aes-256-cfb
     * 
     * @return static
     */
    public function useAes256Cfb(): static
    {
        return $this->setAlgorithm(EncryptAlgorithmEnum::AES_256_CFB);
    }

    /**
     * set algorithm to aes-256-cfb1
     * 
     * @return static
     */
    public function useAes256Cfb1(): static
    {
        return $this->setAlgorithm(EncryptAlgorithmEnum::AES_256_CFB1);
    }

    /**
     * set algorithm to aes-256-cfb8
     * 
     * @return static
     */
    public function useAes256Cfb8(): static
    {
        return $this->setAlgorithm(EncryptAlgorithmEnum::AES_256_CFB8);
    }

    /**
     * set algorithm to aes-256-ctr
     * 
     * @return static
     */
    public function useAes256Ctr(): static
    {
        return $this->setAlgorithm(EncryptAlgorithmEnum::AES_256_CTR);
    }

    /**
     * set algorithm to aes-256-gcm
     * 
     * @return static
     */
    public function useAes256Gcm(): static
    {
        return $this->setAlgorithm(EncryptAlgorithmEnum::AES_256_GCM);
    }

    /**
     * set algorithm to aes-256-ocb
     * 
     * @return static
     */
    public function useAes256Ocb(): static
    {
        return $this->setAlgorithm(EncryptAlgorithmEnum::AES_256_OCB);
    }

    /**
     * set algorithm to aes-256-ofb
     * 
     * @return static
     */
    public function useAes256Ofb(): static
    {
        return $this->setAlgorithm(EncryptAlgorithmEnum::AES_256_OFB);
    }

    /**
     * set algorithm to aes-256-xts
     * 
     * @return static
     */
    public function useAes256Xts(): static
    {
        return $this->setAlgorithm(EncryptAlgorithmEnum::AES_256_XTS);
    }

    /*----------------------------------------*
     * Key
     *----------------------------------------*/

    /**
     * key
     * 
     * @var string|null
     */
    protected string|null $key = null;

    /**
     * get key
     * 
     * @return string|null
     */
    public function key(): string|null
    {
        return $this->key;
    }

    /**
     * set key
     * 
     * @param string $key
     * @return static
     */
    public function setKey(string $key): static
    {
        $this->key = $key;

        return $this;
    }

    /**
     * set hash md5 key
     * 
     * @param string $key
     * @return static
     */
    public function useMd5Key(string $key): static
    {
        return $this->setKey(Crypt::hashMd5($key));
    }

    /**
     * set hash sha256 key
     * 
     * @param string $key
     * @return static
     */
    public function useSha256Key(string $key): static
    {
        return $this->setKey(Crypt::hashSha256($key));
    }

    /**
     * set hash sha512 key
     * 
     * @param string $key
     * @return static
     */
    public function useSha512Key(string $key): static
    {
        return $this->setKey(Crypt::hashSha512($key));
    }

    /**
     * set hash sha3-256 key
     * 
     * @param string $key
     * @return static
     */
    public function useSha3_256Key(string $key): static
    {
        return $this->setKey(Crypt::hashSha3_256($key));
    }

    /**
     * set hash sha3-512 key
     * 
     * @param string $key
     * @return static
     */
    public function useSha3_512Key(string $key): static
    {
        return $this->setKey(Crypt::hashSha3_512($key));
    }

    /*----------------------------------------*
     * Encrypt
     *----------------------------------------*/

    /**
     * encrypt data
     * 
     * @param mixed $data
     * @return string
     */
    public function encrypt(mixed $data): string
    {
        $serialized = serialize($data);

        $ivSize = openssl_cipher_iv_length($this->algorithmValueForce());

        $iv = openssl_random_pseudo_bytes($ivSize);

        $encrypted = openssl_encrypt($serialized, $this->algorithmValueForce(), $this->keyForce(), OPENSSL_RAW_DATA, $iv);

        return base64_encode("$iv$encrypted");
    }

    /*----------------------------------------*
     * Decrypt
     *----------------------------------------*/

    /**
     * decrypt data
     * 
     * @param string $data
     * @return mixed
     */
    public function decrypt(string $data): mixed
    {
        $data = base64_decode($data);

        $ivSize = openssl_cipher_iv_length($this->algorithmValueForce());

        $iv = substr($data, 0, $ivSize);

        $encrypted = substr($data, $ivSize);

        $decrypted = openssl_decrypt($encrypted, $this->algorithmValueForce(), $this->keyForce(), OPENSSL_RAW_DATA, $iv);

        return unserialize($decrypted);
    }

    /*----------------------------------------*
     * Not Public
     *----------------------------------------*/

    /**
     * get algorithm value force
     * 
     * @return string
     */
    protected function algorithmValueForce(): string
    {
        $algorithm = $this->algorithm();

        if (is_null($algorithm)) throw new \Exception("algorithm is not set.");

        return $algorithm->value;
    }

    /**
     * get key force
     * 
     * @return string
     */
    protected function keyForce(): string
    {
        $key = $this->key();

        if (is_null($key)) throw new \Exception("key is not set.");

        return $key;
    }
}
