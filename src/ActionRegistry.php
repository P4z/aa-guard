<?php

declare(strict_types=1);

namespace AAGuard;

final class ActionRegistry
{
    /** @var callable(string):void */
    private $emitter;

    /**
     * @param callable(string):void $emitter
     */
    public function __construct(callable $emitter)
    {
        $this->emitter = $emitter;
    }

    /**
     * @param array<int, string> $templates
     * @param array<string, string> $context
     */
    public function executeTemplates(array $templates, array $context): void
    {
        foreach ($templates as $template) {
            $command = $this->renderTemplate($template, $context);
            ($this->emitter)($command);
        }
    }

    /**
     * @param array<int, string> $templates
     * @param array<string, string> $context
     * @param array<int, string> $rawKeys
     */
    public function executeTemplatesWithRawValues(array $templates, array $context, array $rawKeys): void
    {
        $rawKeyMap = array_fill_keys($rawKeys, true);

        foreach ($templates as $template) {
            $command = $this->renderTemplate($template, $context, $rawKeyMap);
            ($this->emitter)($command);
        }
    }

    /**
     * @param array<string, string> $context
     * @param array<string, bool> $rawKeyMap
     */
    private function renderTemplate(string $template, array $context, array $rawKeyMap = []): string
    {
        // Build replacement map first, then apply all substitutions in one pass
        // (prevents double-substitution when a value contains another {{placeholder}})
        $map = [];
        foreach ($context as $key => $value) {
            $map['{{' . $key . '}}'] = isset($rawKeyMap[$key])
                ? $this->escapeQuotedValue($value)
                : $this->sanitizeValue($value);
        }

        $command = strtr($template, $map);

        return preg_replace('/\s+/', ' ', trim($command)) ?? trim($command);
    }

    private function sanitizeValue(string $value): string
    {
        // Remove control characters
        $value = preg_replace('/[\x00-\x1F\x7F]/', '', $value);
        $value = is_string($value) ? $value : '';
        
        // Normalize whitespace
        $value = preg_replace('/\s+/', ' ', trim($value)) ?? trim($value);
        
        // Remove shell metacharacters to prevent command injection.
        // Keep only safe characters: alphanumeric, space, slash, dash, underscore, dot, @
        $value = preg_replace('/[^a-zA-Z0-9 \/\-_.@]/', '', $value);
        
        return $value;
    }

    private function escapeQuotedValue(string $value): string
    {
        // Keep the original text as much as possible while making it safe to
        // place inside a quoted AA command argument.
        $value = preg_replace('/[\x00-\x1F\x7F]/', ' ', $value);
        $value = is_string($value) ? $value : '';

        return str_replace(['\\', '"'], ['\\\\', '\\"'], $value);
    }
}
