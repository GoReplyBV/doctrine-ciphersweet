<?php

namespace GoReply\DoctrineCiphersweet;

use Doctrine\ORM\EntityManagerInterface;
use InvalidArgumentException;
use ParagonIE\CipherSweet\BlindIndex;
use ParagonIE\CipherSweet\CipherSweet;
use ParagonIE\CipherSweet\EncryptedField;
use RuntimeException;
use function count;
use function is_string;
use function sprintf;
use function str_ends_with;

/**
 * @internal
 */
class Helper
{
    private const MARKER = "\1<ENC>\2";

    /** @var array<class-string, array<string, EncryptedField>> */
    private array $encryptedFieldCache = [];

    public function __construct(
        private CipherSweet $ciphersweet,
        private EntityManagerInterface $entityManager,
    ) {
    }

    public function encrypt(object $object): void
    {
        $meta = $this->entityManager->getClassMetadata($object::class);

        foreach ($this->getEncryptedFields($object::class) as $propertyName => $encryptedField) {
            $plaintext = $meta->getFieldValue($object, $propertyName);
            if (!is_string($plaintext) || str_ends_with($plaintext, self::MARKER)) {
                continue;
            }

            [$ciphertext, $blindIndexes] = $encryptedField->prepareForStorage($plaintext);
            $meta->setFieldValue($object, $propertyName, $ciphertext . self::MARKER);

            foreach ($blindIndexes as $blindIndexPropertyName => $blindIndexCiphertext) {
                $meta->setFieldValue($object, $blindIndexPropertyName, $blindIndexCiphertext);
            }
        }
    }

    public function decrypt(object $object): void
    {
        $meta = $this->entityManager->getClassMetadata($object::class);

        foreach ($this->getEncryptedFields($object::class) as $propertyName => $encryptedField) {
            $ciphertext = $meta->getFieldValue($object, $propertyName);
            if (!is_string($ciphertext) || !str_ends_with($ciphertext, self::MARKER)) {
                continue;
            }

            $ciphertext = substr($ciphertext, 0, -strlen(self::MARKER));

            $plaintext = $encryptedField->decryptValue($ciphertext);
            $meta->setFieldValue($object, $propertyName, $plaintext);

            foreach ($encryptedField->getBlindIndexObjects() as $blindIndex) {
                $meta->setFieldValue($object, $blindIndex->getName(), null);
            }
        }
    }

    /**
     * @param class-string $entityClass
     */
    public function hasEncryptedFields(string $entityClass): bool
    {
        return count($this->getEncryptedFields($entityClass)) > 0;
    }

    /**
     * @param class-string $entityClass
     */
    public function getEncryptedField(string $entityClass, string $propertyName): EncryptedField
    {
        return $this->getEncryptedFields($entityClass)[$propertyName]
            ?? throw new InvalidArgumentException(sprintf(
                'Property %s::%s is not encrypted',
                $entityClass,
                $propertyName
            ));
    }

    /**
     * @param class-string $entityClass
     * @return array<string, EncryptedField>
     */
    private function getEncryptedFields(string $entityClass): array
    {
        return $this->encryptedFieldCache[$entityClass] ??= $this->buildEncryptedFields($entityClass);
    }

    /**
     * @param class-string $entityClass
     * @return array<string, EncryptedField>
     */
    private function buildEncryptedFields(string $entityClass): array
    {
        /** @var array<string, EncryptedField> $encryptedFields */
        $encryptedFields = [];

        $meta = $this->entityManager->getClassMetadata($entityClass);
        $tableName = $meta->getTableName();

        foreach ($meta->getReflectionProperties() as $propertyName => $property) {
            if ($property === null) {
                continue;
            }

            $encryptedFieldAttribute = $property->getAttributes(Attribute\EncryptedField::class)[0] ?? null;
            if ($encryptedFieldAttribute === null) {
                continue;
            }

            $encryptedFields[$propertyName] = new EncryptedField(
                engine: $this->ciphersweet,
                tableName: $tableName,
                fieldName: $propertyName,
            );
        }

        foreach ($meta->getReflectionProperties() as $propertyName => $property) {
            if ($property === null) {
                continue;
            }

            $blindIndexAttribute = $property->getAttributes(Attribute\BlindIndex::class)[0] ?? null;
            if ($blindIndexAttribute === null) {
                continue;
            }

            $blindIndex = $blindIndexAttribute->newInstance();

            if (!isset($encryptedFields[$blindIndex->field])) {
                throw new RuntimeException(sprintf('Unknown encrypted field "%s"', $blindIndex->field));
            }

            $encryptedFields[$blindIndex->field]->addBlindIndex(new BlindIndex(
                name: $propertyName,
                transformations: $blindIndex->transformations,
                filterBits: $blindIndex->filterBits,
                fastHash: $blindIndex->fastHash,
                hashConfig: $blindIndex->hashConfig,
            ));
        }

        return $encryptedFields;
    }
}
