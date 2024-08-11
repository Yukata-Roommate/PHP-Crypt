<?php

namespace YukataRm\Crypt\Interface;

use YukataRm\Crypt\Enum\HashAlgorithmEnum;

/**
 * Hasher Interface
 * 
 * @package YukataRm\Crypt\Interface
 */
interface HasherInterface
{
    /*----------------------------------------*
     * Algorithm
     *----------------------------------------*/

    /**
     * get algorithm
     * 
     * @return \YukataRm\Crypt\Enum\HashAlgorithmEnum|null
     */
    public function algorithm(): HashAlgorithmEnum|null;

    /**
     * set algorithm
     * 
     * @param \YukataRm\Crypt\Enum\HashAlgorithmEnum|string $algorithm
     * @return static
     */
    public function setAlgorithm(HashAlgorithmEnum|string $algorithm): static;

    /**
     * set algorithm to md5
     * 
     * @return static
     */
    public function useMd5(): static;

    /**
     * set algorithm to sha2-256
     * 
     * @return static
     */
    public function useSha256(): static;

    /**
     * set algorithm to sha2-512
     * 
     * @return static
     */
    public function useSha512(): static;

    /**
     * set algorithm to sha3-256
     * 
     * @return static
     */
    public function useSha3_256(): static;

    /**
     * set algorithm to sha3-512
     * 
     * @return static
     */
    public function useSha3_512(): static;

    /*----------------------------------------*
     * Hash
     *----------------------------------------*/

    /**
     * hash string
     * 
     * @param string $data
     * @return string
     */
    public function hash(string $data): string;
}
