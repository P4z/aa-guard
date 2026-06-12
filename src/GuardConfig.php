<?php

declare(strict_types=1);

namespace AAGuard;

final class GuardConfig
{
    /**
     * @param array<int, string> $adminRecipients
     * @param array<int, string> $onConnectActions
     * @param array<int, string> $onMatchActions
     * @param array<int, int>    $retryDelaysMs
     * @param array<int, string> $onMetricsActions  Templates for per-admin metrics messages
     */
    public function __construct(
        public readonly array $adminRecipients,
        public readonly string $onConnectMessageTemplate,
        public readonly array $onConnectActions,
        public readonly array $onMatchActions,
        public readonly array $retryDelaysMs,
        public readonly int $maxAttempts,
        public readonly int $cacheTtlSeconds,
        public readonly int $dedupeWindowSeconds,
        public readonly array $onMetricsActions = [],
        public readonly int $metricsIntervalSeconds = 0,
        public readonly bool $debug = false,
    ) {}
}
