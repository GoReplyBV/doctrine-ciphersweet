<?php

namespace GoReply\DoctrineCiphersweet;

use InvalidArgumentException;
use function sprintf;

class BlindIndexSearchValueProvider
{
    public function __construct(
        private Helper $helper
    ) {
    }

    /**
     * @param class-string $entityClass
     * @return non-empty-array<string, string>
     */
    public function getSearchValues(string $entityClass, string $propertyName, string $searchValue): array
    {
        return $this->helper->getEncryptedField($entityClass, $propertyName)->getAllBlindIndexes($searchValue)
            ?: throw new InvalidArgumentException(sprintf(
                'Property %s::%s has no blind indexes',
                $entityClass,
                $propertyName
            ));
    }
}
