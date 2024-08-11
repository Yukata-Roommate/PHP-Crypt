<?php

namespace YukataRm\Crypt\Interface;

use YukataRm\Crypt\Enum\EncodeAlgorithmEnum;

/**
 * Encoder Interface
 * 
 * @package YukataRm\Crypt\Interface
 */
interface EncoderInterface
{
    /*----------------------------------------*
     * Algorithm
     *----------------------------------------*/

    /**
     * get algorithm
     * 
     * @return \YukataRm\Crypt\Enum\EncodeAlgorithmEnum|null
     */
    public function algorithm(): EncodeAlgorithmEnum|null;

    /**
     * set algorithm
     * 
     * @param \YukataRm\Crypt\Enum\EncodeAlgorithmEnum|string $algorithm
     * @return static
     */
    public function setAlgorithm(EncodeAlgorithmEnum|string $algorithm): static;

    /**
     * set algorithm to base64
     * 
     * @return static
     */
    public function useBase64(): static;

    /**
     * set algorithm to hex
     * 
     * @return static
     */
    public function useHex(): static;

    /*----------------------------------------*
     * Encode
     *----------------------------------------*/

    /**
     * encode string
     * 
     * @param string $data
     * @return string
     */
    public function encode(string $data): string;

    /*----------------------------------------*
     * Decode
     *----------------------------------------*/

    /**
     * decode string
     * 
     * @param string $data
     * @return string
     */
    public function decode(string $data): string;
}
