<?php

namespace YukataRm\Crypt\Interface;

use YukataRm\Crypt\Enum\EncryptAlgorithmEnum;

/**
 * Encrypter Interface
 * 
 * @package YukataRm\Crypt\Interface
 */
interface EncrypterInterface
{
    /*----------------------------------------*
     * Algorithm
     *----------------------------------------*/

    /**
     * get algorithm
     * 
     * @return \YukataRm\Crypt\Enum\EncryptAlgorithmEnum|null
     */
    public function algorithm(): EncryptAlgorithmEnum|null;

    /**
     * set algorithm
     * 
     * @param \YukataRm\Crypt\Enum\EncryptAlgorithmEnum|string $algorithm
     * @return static
     */
    public function setAlgorithm(EncryptAlgorithmEnum|string $algorithm): static;

    /**
     * set algorithm to aes-256-cbc
     * 
     * @return static
     */
    public function useAes256Cbc(): static;

    /**
     * set algorithm to aes-256-ccm
     * 
     * @return static
     */
    public function useAes256Ccm(): static;

    /**
     * set algorithm to aes-256-cfb
     * 
     * @return static
     */
    public function useAes256Cfb(): static;

    /**
     * set algorithm to aes-256-cfb1
     * 
     * @return static
     */
    public function useAes256Cfb1(): static;

    /**
     * set algorithm to aes-256-cfb8
     * 
     * @return static
     */
    public function useAes256Cfb8(): static;

    /**
     * set algorithm to aes-256-ctr
     * 
     * @return static
     */
    public function useAes256Ctr(): static;

    /**
     * set algorithm to aes-256-gcm
     * 
     * @return static
     */
    public function useAes256Gcm(): static;

    /**
     * set algorithm to aes-256-ocb
     * 
     * @return static
     */
    public function useAes256Ocb(): static;

    /**
     * set algorithm to aes-256-ofb
     * 
     * @return static
     */
    public function useAes256Ofb(): static;

    /**
     * set algorithm to aes-256-xts
     * 
     * @return static
     */
    public function useAes256Xts(): static;

    /*----------------------------------------*
     * Key
     *----------------------------------------*/

    /**
     * get key
     * 
     * @return string|null
     */
    public function key(): string|null;

    /**
     * set key
     * 
     * @param string $key
     * @return static
     */
    public function setKey(string $key): static;

    /**
     * set hash md5 key
     * 
     * @param string $key
     * @return static
     */
    public function useMd5Key(string $key): static;

    /**
     * set hash sha256 key
     * 
     * @param string $key
     * @return static
     */
    public function useSha256Key(string $key): static;

    /**
     * set hash sha512 key
     * 
     * @param string $key
     * @return static
     */
    public function useSha512Key(string $key): static;

    /**
     * set hash sha3-256 key
     * 
     * @param string $key
     * @return static
     */
    public function useSha3_256Key(string $key): static;

    /**
     * set hash sha3-512 key
     * 
     * @param string $key
     * @return static
     */
    public function useSha3_512Key(string $key): static;

    /*----------------------------------------*
     * Encrypt
     *----------------------------------------*/

    /**
     * encrypt data
     * 
     * @param mixed $data
     * @return string
     */
    public function encrypt(mixed $data): string;

    /*----------------------------------------*
     * Decrypt
     *----------------------------------------*/

    /**
     * decrypt data
     * 
     * @param string $data
     * @return mixed
     */
    public function decrypt(string $data): mixed;
}
