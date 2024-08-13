<?php

namespace YukataRm\Crypt;

use YukataRm\Crypt\Interface\HasherInterface;

use YukataRm\Crypt\Enum\HashAlgorithmEnum;

/**
 * Hasher
 * 
 * @package YukataRm\Crypt
 */
class Hasher implements HasherInterface
{
    /*----------------------------------------*
     * Algorithm
     *----------------------------------------*/

    /**
     * algorithm
     * 
     * @var \YukataRm\Crypt\Enum\HashAlgorithmEnum|null
     */
    protected HashAlgorithmEnum|null $algorithm = null;

    /**
     * get algorithm
     * 
     * @return \YukataRm\Crypt\Enum\HashAlgorithmEnum|null
     */
    public function algorithm(): HashAlgorithmEnum|null
    {
        return $this->algorithm;
    }

    /**
     * set algorithm
     * 
     * @param \YukataRm\Crypt\Enum\HashAlgorithmEnum|string $algorithm
     * @return static
     */
    public function setAlgorithm(HashAlgorithmEnum|string $algorithm): static
    {
        if (is_string($algorithm)) $algorithm = HashAlgorithmEnum::tryFrom($algorithm);

        $this->algorithm = $algorithm;

        return $this;
    }

    /**
     * set algorithm to md5
     * 
     * @return static
     */
    public function useMd5(): static
    {
        return $this->setAlgorithm(HashAlgorithmEnum::MD5);
    }

    /**
     * set algorithm to sha2-256
     * 
     * @return static
     */
    public function useSha256(): static
    {
        return $this->setAlgorithm(HashAlgorithmEnum::SHA2_256);
    }

    /**
     * set algorithm to sha2-512
     * 
     * @return static
     */
    public function useSha512(): static
    {
        return $this->setAlgorithm(HashAlgorithmEnum::SHA2_512);
    }

    /**
     * set algorithm to sha3-256
     * 
     * @return static
     */
    public function useSha3_256(): static
    {
        return $this->setAlgorithm(HashAlgorithmEnum::SHA3_256);
    }

    /**
     * set algorithm to sha3-512
     * 
     * @return static
     */
    public function useSha3_512(): static
    {
        return $this->setAlgorithm(HashAlgorithmEnum::SHA3_512);
    }

    /*----------------------------------------*
     * Hash
     *----------------------------------------*/

    /**
     * hash string
     * 
     * @param string $data
     * @return string
     */
    public function hash(string $data): string
    {
        return hash($this->algorithmValueForce(), $data);
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
}
