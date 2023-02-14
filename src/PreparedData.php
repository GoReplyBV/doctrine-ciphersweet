<?php

namespace GoReply\DoctrineCiphersweet;

class PreparedData
{
    /**
     * @param array<string, string> $blindIndexes
     */
    public function __construct(
        public readonly string $plaintext,
        public readonly string $ciphertext,
        public readonly array $blindIndexes,
    ) {
    }
}
