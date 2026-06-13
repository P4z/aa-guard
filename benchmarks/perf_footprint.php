#!/usr/bin/env php
<?php

declare(strict_types=1);

use AAGuard\ActionRegistry;
use AAGuard\Guard;
use AAGuard\GuardConfig;
use AAGuard\IpInfoClient;
use AAGuard\Logger;
use AAGuard\Matcher;
use AAGuard\Metrics;

require_once __DIR__ . '/../src/autoload.php';

const HOUSEKEEPING_ITERATIONS = 3000;
const HOUSEKEEPING_CACHE_SIZE = 30000;
const HOUSEKEEPING_ACTIONS_SIZE = 30000;

const RATE_LIMIT_ITERATIONS = 3000;
const RATE_LIMIT_TIMESTAMP_SIZE = 50000;

/**
 * @return array{seconds:float,memoryDeltaBytes:int,peakDeltaBytes:int}
 */
function runMeasured(callable $fn): array
{
    gc_collect_cycles();
    if (function_exists('memory_reset_peak_usage')) {
        memory_reset_peak_usage();
    }

    $startMem = memory_get_usage(true);
    $start = hrtime(true);

    $fn();

    $end = hrtime(true);
    $endMem = memory_get_usage(true);
    $peak = memory_get_peak_usage(true);

    return [
        'seconds' => ($end - $start) / 1_000_000_000,
        'memoryDeltaBytes' => $endMem - $startMem,
        'peakBytes' => $peak,
    ];
}

/**
 * @return Guard
 */
function makeGuardForBenchmark(): Guard
{
    $ipInfoClient = new IpInfoClient('https://ipinfo.io', null, 2, 30, new Metrics());
    $matcher = new Matcher([['name' => 'none', 'pattern' => '/^never-match$/']]);
    $actions = new ActionRegistry(static function (string $command): void {
        // no-op
    });
    $logger = new Logger(static function (string $level, string $message): void {
        // no-op
    });

    return new Guard(
        $ipInfoClient,
        $matcher,
        $actions,
        $logger,
        new GuardConfig(
            adminRecipients: [],
            onConnectMessageTemplate: '{{player_id}}',
            onConnectActions: [],
            onMatchActions: [],
            retryDelaysMs: [100],
            maxAttempts: 1,
            cacheTtlSeconds: 1800,
            dedupeWindowSeconds: 15
        ),
        new Metrics()
    );
}

/**
 * @return array<string,mixed>
 */
function benchmarkHousekeeping(): array
{
    $guard = makeGuardForBenchmark();
    $now = microtime(true);

    $ipCache = [];
    for ($i = 0; $i < HOUSEKEEPING_CACHE_SIZE; $i++) {
        $ipCache['10.10.' . intdiv($i, 255) . '.' . ($i % 255)] = [
            'networkName' => 'Benchmark ISP',
            'country' => 'BenchmarkLand',
            'countryCode' => 'BL',
            'countryName' => 'BenchmarkLand',
            'expiresAt' => $now + 120.0,
        ];
    }

    $recentActions = [];
    for ($i = 0; $i < HOUSEKEEPING_ACTIONS_SIZE; $i++) {
        $recentActions['player' . $i . '|rule' . ($i % 7)] = $now;
    }

    $guardReflection = new ReflectionClass($guard);
    $ipCacheProp = $guardReflection->getProperty('ipCache');
    $ipCacheProp->setAccessible(true);
    $ipCacheProp->setValue($guard, $ipCache);

    $recentActionsProp = $guardReflection->getProperty('recentActions');
    $recentActionsProp->setAccessible(true);
    $recentActionsProp->setValue($guard, $recentActions);

    $result = runMeasured(static function () use ($guard): void {
        for ($i = 0; $i < HOUSEKEEPING_ITERATIONS; $i++) {
            $guard->housekeeping();
        }
    });

    return [
        'scenario' => 'guard_housekeeping',
        'iterations' => HOUSEKEEPING_ITERATIONS,
        'ipCacheSize' => HOUSEKEEPING_CACHE_SIZE,
        'recentActionsSize' => HOUSEKEEPING_ACTIONS_SIZE,
    ] + $result;
}

/**
 * @return array<string,mixed>
 */
function benchmarkRateLimiterPrune(): array
{
    $client = new IpInfoClient('https://ipinfo.io', null, 2, 999999, new Metrics());
    $now = microtime(true);
    $timestamps = [];

    // First half expired (older than 60s), second half still active.
    for ($i = 0; $i < RATE_LIMIT_TIMESTAMP_SIZE; $i++) {
        if ($i < RATE_LIMIT_TIMESTAMP_SIZE / 2) {
            $timestamps[] = $now - 75.0;
            continue;
        }
        $timestamps[] = $now - 10.0;
    }

    $clientReflection = new ReflectionClass($client);
    $timestampsProp = $clientReflection->getProperty('apiCallTimestamps');
    $timestampsProp->setAccessible(true);
    $timestampsProp->setValue($client, $timestamps);

    if ($clientReflection->hasProperty('apiCallStartIndex')) {
        $startIndexProp = $clientReflection->getProperty('apiCallStartIndex');
        $startIndexProp->setAccessible(true);
        $startIndexProp->setValue($client, 0);
    }

    $result = runMeasured(static function () use ($client): void {
        for ($i = 0; $i < RATE_LIMIT_ITERATIONS; $i++) {
            $client->isRateLimited();
        }
    });

    return [
        'scenario' => 'ipinfo_rate_limit_prune',
        'iterations' => RATE_LIMIT_ITERATIONS,
        'timestamps' => RATE_LIMIT_TIMESTAMP_SIZE,
    ] + $result;
}

$benchmarks = [
    benchmarkHousekeeping(),
    benchmarkRateLimiterPrune(),
];

$output = [
    'phpVersion' => PHP_VERSION,
    'timestampUtc' => gmdate('c'),
    'benchmarks' => $benchmarks,
];

echo json_encode($output, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
