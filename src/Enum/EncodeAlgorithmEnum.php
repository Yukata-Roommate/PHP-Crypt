<?php

namespace YukataRm\Crypt\Enum;

/**
 * Encode Algorithm Enum
 * 
 * @package YukataRm\Crypt\Enum
 */
enum EncodeAlgorithmEnum: string
{
    case BASE64 = "base64";
    case HEX    = "hex";
}
