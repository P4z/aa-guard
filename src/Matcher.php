<?php

declare(strict_types=1);

namespace AAGuard;

final class Matcher
{
    /** @var array<int, array{name:string, pattern:string}> */
    private array $rules;
    private ?Logger $logger;

    /**
     * @param array<int, array{name:string, pattern:string}> $rules
     */
    public function __construct(array $rules, ?Logger $logger = null)
    {
        $this->rules = $rules;
        $this->logger = $logger;
    }

    /**
     * @return array{matched:bool, ruleName:?string, pattern:?string}
     */
    public function match(string $networkName): array
    {
        foreach ($this->rules as $rule) {
            $pattern = $rule['pattern'];

            // Execute pattern match with error handling (no @ suppression)
            $result = preg_match($pattern, $networkName);

            // Check for regex errors
            if ($result === false) {
                $errorCode = preg_last_error();
                $errorMsg = $this->getPregErrorMessage($errorCode);
                $message = sprintf('Regex error in pattern "%s": %s', $pattern, $errorMsg);
                if ($this->logger !== null) {
                    $this->logger->error($message);
                } else {
                    error_log($message);
                }
                continue; // Skip this rule and try the next one
            }

            if ($result === 1) {
                return [
                    'matched' => true,
                    'ruleName' => $rule['name'],
                    'pattern' => $pattern,
                ];
            }
        }

        return [
            'matched' => false,
            'ruleName' => null,
            'pattern' => null,
        ];
    }

    private function getPregErrorMessage(int $errorCode): string
    {
        return match ($errorCode) {
            PREG_NO_ERROR => 'No error',
            PREG_INTERNAL_ERROR => 'Internal PCRE error',
            PREG_BACKTRACK_LIMIT_ERROR => 'Backtrack limit exhausted',
            PREG_RECURSION_LIMIT_ERROR => 'Recursion limit exhausted',
            PREG_BAD_UTF8_ERROR => 'Malformed UTF-8',
            PREG_BAD_UTF8_OFFSET_ERROR => 'Bad UTF-8 offset',
            PREG_JIT_STACKLIMIT_ERROR => 'JIT stack limit exhausted',
            default => 'Unknown PCRE error',
        };
    }
}
