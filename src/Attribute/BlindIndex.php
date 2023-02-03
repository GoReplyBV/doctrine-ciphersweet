<?php

namespace GoReply\DoctrineCiphersweet\Attribute;

use Attribute;
use ParagonIE\CipherSweet\Contract\TransformationInterface;

#[Attribute(Attribute::TARGET_PROPERTY)]
class BlindIndex
{
    /**
     * @param array<int, TransformationInterface> $transformations
     * @param array<mixed> $hashConfig
     */
    public function __construct(
        public readonly string $field,
        public readonly array $transformations = [],
        public readonly int $filterBits = 256,
        public readonly bool $fastHash = false,
        public readonly array $hashConfig = []
    ) {
    }
}
