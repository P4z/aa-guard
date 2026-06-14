<?php

declare(strict_types=1);

namespace AAGuard;

final class Metrics
{
    private float $startedAt;

    public int $lookups = 0;
    public int $cacheHits = 0;
    public int $apiErrors = 0;
    public int $rateLimited = 0;
    public int $bans = 0;
    public int $invalidIps = 0;
    public string $lastActionWho = 'none';
    public string $lastActionWhy = 'none';

    public function __construct()
    {
        $this->startedAt = microtime(true);
    }

    /** @return array<string, string> */
    public function toTemplateContext(): array
    {
        $runtimeSeconds = $this->getRuntimeSeconds();

        return [
            'bans'         => (string) $this->bans,
            'lookups'      => (string) $this->lookups,
            'cache_hits'   => (string) $this->cacheHits,
            'api_errors'   => (string) $this->apiErrors,
            'rate_limited' => (string) $this->rateLimited,
            'invalid_ips'  => (string) $this->invalidIps,
            'last_action_who' => $this->lastActionWho,
            'last_action_why' => $this->lastActionWhy,
            'runtime'      => $this->formatRuntime($runtimeSeconds),
        ];
    }

    public function recordLastAction(string $who, string $why): void
    {
        $trimmedWho = trim($who);
        $trimmedWhy = trim($why);

        $this->lastActionWho = $trimmedWho !== '' ? $trimmedWho : 'unknown';
        $this->lastActionWhy = $trimmedWhy !== '' ? $trimmedWhy : 'unknown';
    }

    public function toLogString(): string
    {
        $runtimeSeconds = $this->getRuntimeSeconds();

        return sprintf(
            'Metrics: bans=%d lookups=%d cache_hits=%d api_errors=%d rate_limited=%d invalid_ips=%d last_action_who=%s last_action_why=%s runtime=%s',
            $this->bans,
            $this->lookups,
            $this->cacheHits,
            $this->apiErrors,
            $this->rateLimited,
            $this->invalidIps,
            $this->lastActionWho,
            $this->lastActionWhy,
            $this->formatRuntime($runtimeSeconds)
        );
    }

    private function getRuntimeSeconds(): int
    {
        return max(0, (int) floor(microtime(true) - $this->startedAt));
    }

    private function formatRuntime(int $runtimeSeconds): string
    {
        // Dynamic format: y/mo/d/h/m, zero-value units omitted, seconds ignored.
        $remainingMinutes = intdiv($runtimeSeconds, 60);
        $units = [
            'y'  => 365 * 24 * 60,
            'mo' => 30 * 24 * 60,
            'd'  => 24 * 60,
            'h'  => 60,
            'm'  => 1,
        ];

        $parts = [];

        foreach ($units as $suffix => $unitMinutes) {
            $value = intdiv($remainingMinutes, $unitMinutes);
            if ($value > 0) {
                $parts[] = sprintf('%d%s', $value, $suffix);
            }
            $remainingMinutes %= $unitMinutes;
        }

        return $parts === [] ? '0m' : implode(' ', $parts);
    }
}
