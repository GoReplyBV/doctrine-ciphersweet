<?php

use PhpCsFixer\Fixer\CastNotation\CastSpacesFixer;
use PhpCsFixer\Fixer\Import\GlobalNamespaceImportFixer;
use PhpCsFixer\Fixer\Operator\NotOperatorWithSuccessorSpaceFixer;
use PhpCsFixer\Fixer\Phpdoc\PhpdocLineSpanFixer;
use PhpCsFixer\Fixer\Strict\DeclareStrictTypesFixer;
use PhpCsFixer\Fixer\StringNotation\NoTrailingWhitespaceInStringFixer;
use PhpCsFixer\Fixer\Whitespace\HeredocIndentationFixer;
use Symplify\CodingStandard\Fixer\LineLength\LineLengthFixer;
use Symplify\EasyCodingStandard\Config\ECSConfig;
use Symplify\EasyCodingStandard\ValueObject\Set\SetList;

return function (ECSConfig $config): void {
    $config->parallel();

    $config->paths([__DIR__ . '/src', __FILE__]);

    $config->sets([SetList::CLEAN_CODE, SetList::COMMON, SetList::PSR_12]);

    $config->rules([LineLengthFixer::class, NoTrailingWhitespaceInStringFixer::class]);

    $config->ruleWithConfiguration(CastSpacesFixer::class, [
        'space' => 'none',
    ]);

    $config->ruleWithConfiguration(GlobalNamespaceImportFixer::class, [
        'import_classes' => true,
        'import_constants' => true,
        'import_functions' => true,
    ]);

    $config->ruleWithConfiguration(HeredocIndentationFixer::class, [
        'indentation' => 'same_as_start',
    ]);

    $config->ruleWithConfiguration(PhpdocLineSpanFixer::class, [
        'const' => 'single',
        'property' => 'single',
        'method' => 'multi',
    ]);

    $config->skip([DeclareStrictTypesFixer::class, NotOperatorWithSuccessorSpaceFixer::class]);
};
