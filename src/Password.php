<?php

namespace YukataRm\Crypt;

use YukataRm\Crypt\Interface\PasswordInterface;

use YukataRm\Crypt\Enum\PasswordAlgorithmEnum;

/**
 * Password
 * 
 * @package YukataRm\Crypt
 */
class Password implements PasswordInterface
{
    /*----------------------------------------*
     * Algorithm
     *----------------------------------------*/

    /**
     * algorithm
     * 
     * @var \YukataRm\Crypt\Enum\PasswordAlgorithmEnum|null
     */
    protected PasswordAlgorithmEnum|null $algorithm = null;

    /**
     * get algorithm
     * 
     * @return \YukataRm\Crypt\Enum\PasswordAlgorithmEnum|null
     */
    public function algorithm(): PasswordAlgorithmEnum|null
    {
        return $this->algorithm;
    }

    /**
     * get algorithm constant
     * 
     * @return string|null
     */
    public function algorithmConstant(): string|null
    {
        $algorithm = $this->algorithm();

        return is_null($algorithm) ? null : $algorithm->constant();
    }

    /**
     * set algorithm
     * 
     * @param \YukataRm\Crypt\Enum\PasswordAlgorithmEnum|string $algorithm
     * @return static
     */
    public function setAlgorithm(PasswordAlgorithmEnum|string $algorithm): static
    {
        if (is_string($algorithm)) $algorithm = PasswordAlgorithmEnum::tryFrom($algorithm);

        $this->algorithm = $algorithm;

        return $this;
    }

    /**
     * set algorithm to default
     * 
     * @return static
     */
    public function useDefault(): static
    {
        return $this->setAlgorithm(PasswordAlgorithmEnum::DEFAULT);
    }

    /**
     * set algorithm to bcrypt
     * 
     * @return static
     */
    public function useBcrypt(): static
    {
        return $this->setAlgorithm(PasswordAlgorithmEnum::BCRYPT);
    }

    /**
     * set algorithm to argon2i
     * 
     * @return static
     */
    public function useArgon2i(): static
    {
        return $this->setAlgorithm(PasswordAlgorithmEnum::ARGON2I);
    }

    /**
     * set algorithm to argon2id
     * 
     * @return static
     */
    public function useArgon2id(): static
    {
        return $this->setAlgorithm(PasswordAlgorithmEnum::ARGON2ID);
    }

    /*----------------------------------------*
     * Options
     *----------------------------------------*/

    /**
     * options
     * 
     * @var array<string, mixed>
     */
    protected array $options = [];

    /**
     * get options
     * 
     * @return array<string, mixed>
     */
    public function options(): array
    {
        return $this->options;
    }

    /**
     * set options
     * 
     * @param array<string, mixed> $options
     * @return static
     */
    public function setOptions(array $options): static
    {
        $this->options = $options;

        return $this;
    }

    /**
     * add option
     * 
     * @param string $name
     * @param mixed $value
     * @return static
     */
    public function addOption(string $name, mixed $value): static
    {
        $this->options[$name] = $value;

        return $this;
    }

    /**
     * add salt option
     * 
     * @param string $salt
     * @return static
     */
    public function addSalt(string $salt): static
    {
        return $this->addOption("salt", $salt);
    }

    /**
     * add cost option
     * 
     * @param int $cost
     * @return static
     */
    public function addCost(int $cost): static
    {
        return $this->addOption("cost", $cost);
    }

    /**
     * add memory cost option
     * 
     * @param int $memoryCost
     * @return static
     */
    public function addMemoryCost(int $memoryCost): static
    {
        return $this->addOption("memory_cost", $memoryCost);
    }

    /**
     * add time cost option
     * 
     * @param int $timeCost
     * @return static
     */
    public function addTimeCost(int $timeCost): static
    {
        return $this->addOption("time_cost", $timeCost);
    }

    /**
     * add threads option
     * 
     * @param int $threads
     * @return static
     */
    public function addThreads(int $threads): static
    {
        return $this->addOption("threads", $threads);
    }

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
    public function generate(string $characters, int $length): string
    {
        return substr(str_shuffle(str_repeat($characters, $length)), 0, $length);
    }

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
    ): string {
        $characters = $addCharacters ?? "";

        if ($useAlphabet) $characters .= $this->alphabet();
        if ($useNumeric)  $characters .= $this->numeric();
        if ($useSymbol)   $characters .= $this->symbol();

        return $this->generate($characters, $length);
    }

    /**
     * make hash
     * 
     * @param string $data
     * @return string
     */
    public function hash(string $data): string
    {
        return password_hash(
            $data,
            $this->algorithmConstantForce(),
            $this->options
        );
    }

    /**
     * verify hash
     * 
     * @param string $data
     * @param string $hash
     * @return bool
     */
    public function verify(string $data, string $hash): bool
    {
        return password_verify($data, $hash);
    }

    /**
     * check if hash needs to be rehashed
     * 
     * @param string $hash
     * @return bool
     */
    public function needsRehash(string $hash): bool
    {
        return password_needs_rehash(
            $hash,
            $this->algorithmConstantForce(),
            $this->options
        );
    }

    /**
     * rehash hash if needed
     * 
     * @param string $hash
     * @return string
     */
    public function rehashIfNeeded(string $hash): string
    {
        return $this->needsRehash($hash) ? $this->hash($hash) : $hash;
    }

    /*----------------------------------------*
     * Not Public
     *----------------------------------------*/

    /**
     * get algorithm constant force
     * 
     * @return string
     */
    protected function algorithmConstantForce(): string
    {
        $algorithm = $this->algorithmConstant();

        if (is_null($algorithm)) throw new \Exception("algorithm is not set.");

        return $algorithm;
    }

    /**
     * get alphabet characters
     * 
     * @return string
     */
    protected function alphabet(): string
    {
        return "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    }

    /**
     * get numeric characters
     * 
     * @return string
     */
    protected function numeric(): string
    {
        return "0123456789";
    }

    /**
     * get symbol characters
     * 
     * @return string
     */
    protected function symbol(): string
    {
        return "!@#$%^&*()-_=+[]{};:,.<>?/~";
    }
}
