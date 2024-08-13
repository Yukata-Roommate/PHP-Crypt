<?php

namespace YukataRm\Crypt\Interface;

use YukataRm\Crypt\Enum\PasswordAlgorithmEnum;

/**
 * Password Interface
 * 
 * @package YukataRm\Crypt\Interface
 */
interface PasswordInterface
{
    /*----------------------------------------*
     * Algorithm
     *----------------------------------------*/

    /**
     * get algorithm
     * 
     * @return \YukataRm\Crypt\Enum\PasswordAlgorithmEnum|null
     */
    public function algorithm(): PasswordAlgorithmEnum|null;

    /**
     * set algorithm
     * 
     * @param \YukataRm\Crypt\Enum\PasswordAlgorithmEnum|string $algorithm
     * @return static
     */
    public function setAlgorithm(PasswordAlgorithmEnum|string $algorithm): static;

    /**
     * set algorithm to default
     * 
     * @return static
     */
    public function useDefault(): static;

    /**
     * set algorithm to bcrypt
     * 
     * @return static
     */
    public function useBcrypt(): static;

    /**
     * set algorithm to argon2i
     * 
     * @return static
     */
    public function useArgon2i(): static;

    /**
     * set algorithm to argon2id
     * 
     * @return static
     */
    public function useArgon2id(): static;

    /*----------------------------------------*
     * Options
     *----------------------------------------*/

    /**
     * get options
     * 
     * @return array<string, mixed>
     */
    public function options(): array;

    /**
     * set options
     * 
     * @param array<string, mixed> $options
     * @return static
     */
    public function setOptions(array $options): static;

    /**
     * add option
     * 
     * @param string $name
     * @param mixed $value
     * @return static
     */
    public function addOption(string $name, mixed $value): static;

    /**
     * add salt option
     * 
     * @param string $salt
     * @return static
     */
    public function addSalt(string $salt): static;

    /**
     * add cost option
     * 
     * @param int $cost
     * @return static
     */
    public function addCost(int $cost): static;

    /**
     * add memory cost option
     * 
     * @param int $memoryCost
     * @return static
     */
    public function addMemoryCost(int $memoryCost): static;

    /**
     * add time cost option
     * 
     * @param int $timeCost
     * @return static
     */
    public function addTimeCost(int $timeCost): static;

    /**
     * add threads option
     * 
     * @param int $threads
     * @return static
     */
    public function addThreads(int $threads): static;

    /*----------------------------------------*
     * Password
     *----------------------------------------*/

    /**
     * generate
     * 
     * @param string $characters
     * @param int $length
     * @return string
     */
    public function generate(string $characters, int $length): string;

    /**
     * generate by
     * 
     * @param int $length
     * @param bool $useAlphabet
     * @param bool $useNumeric
     * @param bool $useSymbol
     * @param string|null $addCharacters
     * @return string
     */
    public function generateBy(
        int $length,
        bool $useAlphabet = true,
        bool $useNumeric = true,
        bool $useSymbol = true,
        string|null $addCharacters = null
    ): string;

    /**
     * make hash
     * 
     * @param string $data
     * @return string
     */
    public function hash(string $data): string;

    /**
     * verify hash
     * 
     * @param string $data
     * @param string $hash
     * @return bool
     */
    public function verify(string $data, string $hash): bool;

    /**
     * check if hash needs to be rehashed
     * 
     * @param string $hash
     * @return bool
     */
    public function needsRehash(string $hash): bool;

    /**
     * rehash hash if needed
     * 
     * @param string $hash
     * @return string
     */
    public function rehashIfNeeded(string $hash): string;
}
