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
     * @param array<int, string> $onErrorQuotes      Random reply quotes for unhandled/unauthorized /guard invocations
     * @param array<int, string> $onErrorActions     Action templates delivering the picked onErrorQuotes entry (may reference {{msg}}, {{player_id}})
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
        public readonly array $onErrorQuotes = [],
        public readonly array $onErrorActions = [],
    ) {}
}
