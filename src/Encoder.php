<?php

namespace YukataRm\Crypt;

use YukataRm\Crypt\Interface\EncoderInterface;

use YukataRm\Crypt\Enum\EncodeAlgorithmEnum;

/**
 * Encoder
 * 
 * @package YukataRm\Crypt
 */
class Encoder implements EncoderInterface
{
    /*----------------------------------------*
     * Algorithm
     *----------------------------------------*/

    /**
     * algorithm
     * 
     * @var \YukataRm\Crypt\Enum\EncodeAlgorithmEnum|null
     */
    protected EncodeAlgorithmEnum|null $algorithm = null;

    /**
     * get algorithm
     * 
     * @return \YukataRm\Crypt\Enum\EncodeAlgorithmEnum|null
     */
    public function algorithm(): EncodeAlgorithmEnum|null
    {
        return $this->algorithm;
    }

    /**
     * set algorithm
     * 
     * @param \YukataRm\Crypt\Enum\EncodeAlgorithmEnum|string $algorithm
     * @return static
     */
    public function setAlgorithm(EncodeAlgorithmEnum|string $algorithm): static
    {
        if (is_string($algorithm)) $algorithm = EncodeAlgorithmEnum::tryFrom($algorithm);

        $this->algorithm = $algorithm;

        return $this;
    }

    /**
     * set algorithm to base64
     * 
     * @return static
     */
    public function useBase64(): static
    {
        return $this->setAlgorithm(EncodeAlgorithmEnum::BASE64);
    }

    /**
     * set algorithm to hex
     * 
     * @return static
     */
    public function useHex(): static
    {
        return $this->setAlgorithm(EncodeAlgorithmEnum::HEX);
    }

    /*----------------------------------------*
     * Encode
     *----------------------------------------*/

    /**
     * encode string
     * 
     * @param string $data
     * @return string
     */
    public function encode(string $data): string
    {
        $algorithm = $this->algorithm();

        if (is_null($algorithm)) throw new \Exception("encode algorithm is not set.");

        return match ($algorithm) {
            EncodeAlgorithmEnum::BASE64 => base64_encode($data),
            EncodeAlgorithmEnum::HEX    => bin2hex($data),

            default                     => throw new \Exception("encode algorithm is not valid."),
        };
    }

    /*----------------------------------------*
     * Decode
     *----------------------------------------*/

    /**
     * decode string
     * 
     * @param string $data
     * @return string
     */
    public function decode(string $data): string
    {
        $algorithm = $this->algorithm();

        if (is_null($algorithm)) throw new \Exception("decode algorithm is not set.");

        return match ($algorithm) {
            EncodeAlgorithmEnum::BASE64 => base64_decode($data),
            EncodeAlgorithmEnum::HEX    => hex2bin($data),

            default                     => throw new \Exception("decode algorithm is not valid."),
        };
    }
}
