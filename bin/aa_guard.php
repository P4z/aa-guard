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

/** Interval between loop iterations in microseconds */
const STREAM_SELECT_INTERVAL_US = 200_000;

$configPath = $argv[1] ?? (__DIR__ . '/../config/aa_guard.json');
$config = loadConfig($configPath);

$metrics = new Metrics();
$ipInfoToken = getenv('IPINFO_TOKEN');
$ipInfoClient = new IpInfoClient(
    'https://ipinfo.io',
    is_string($ipInfoToken) ? $ipInfoToken : null,
    $config['ipInfoTimeoutSeconds'],
    $config['ipInfoRateLimitPerMinute'],
    $metrics
);
$actions = new ActionRegistry(static function (string $command): void {
    fwrite(STDOUT, $command . PHP_EOL);
    fflush(STDOUT);
});
$logger = new Logger(
    static function (string $level, string $message) use ($config, $actions): void {
        if (($config['debug'] ?? false) !== true) {
            return;
        }

        foreach ($config['admins'] as $admin) {
            $actions->executeTemplatesWithRawValues([
                ...$config['actions']['onDebug'],
            ], [
                'admin' => $admin,
                'level' => $level,
                'msg' => $message,
            ], ['msg']);
        }
    }
);
$matcher = new Matcher($config['rules'], $logger);

$guard = new Guard(
    $ipInfoClient,
    $matcher,
    $actions,
    $logger,
    new GuardConfig(
        adminRecipients:     $config['admins'],
        onConnectMessageTemplate: $config['actions']['onConnectMessage'],
        onConnectActions:    $config['actions']['onConnect'],
        onMatchActions:      $config['actions']['onMatch'],
        retryDelaysMs:       $config['retry']['delaysMs'],
        maxAttempts:         $config['retry']['maxAttempts'],
        cacheTtlSeconds:     $config['cacheTtlSeconds'],
        dedupeWindowSeconds: $config['dedupeWindowSeconds'],
        onMetricsActions:    $config['actions']['onMetrics'],
        metricsIntervalSeconds: $config['metricsIntervalSeconds'],
        debug:               $config['debug'],
    ),
    $metrics
);

stream_set_blocking(STDIN, false);
$actions->executeTemplates($config['actions']['onStartup'], []);
$logger->debug('AA guard started');

$running = true;
$reportMetricsPending = false;
if (function_exists('pcntl_async_signals')) {
    pcntl_async_signals(true);
    pcntl_signal(SIGTERM, static function () use (&$running): void {
        $running = false;
    });
    pcntl_signal(SIGINT, static function () use (&$running): void {
        $running = false;
    });
    pcntl_signal(SIGUSR1, static function () use (&$reportMetricsPending): void {
        $reportMetricsPending = true;
    });
}

$lastMetricsAt = microtime(true);

while ($running) {
    $read = [STDIN];
    $write = [];
    $except = [];

    $result = stream_select($read, $write, $except, 0, STREAM_SELECT_INTERVAL_US);
    if ($result === false) {
        $logger->error('stream_select failed, stopping guard');
        exit(1);
    }

    if ($result > 0) {
        while (($line = fgets(STDIN)) !== false) {
            $guard->handleLogLine($line);
        }

        if (feof(STDIN)) {
            $logger->warning('STDIN closed, stopping guard');
            break;
        }
    }

    $guard->processPendingChecks();
    $guard->housekeeping();

    // Periodic metrics reporting (disabled when metricsIntervalSeconds === 0)
    $metricsInterval = $guard->getConfig()->metricsIntervalSeconds;
    $now = microtime(true);
    if ($reportMetricsPending || ($metricsInterval > 0 && ($now - $lastMetricsAt) >= $metricsInterval)) {
        $guard->reportMetrics();
        $lastMetricsAt = $now;
        $reportMetricsPending = false;
    }
}

function loadConfig(string $configPath): array
{
    if (!is_file($configPath)) {
        fwrite(STDERR, "Config file not found: {$configPath}\n");
        exit(2);
    }

    $raw = file_get_contents($configPath);
    if ($raw === false) {
        fwrite(STDERR, "Failed to read config file: {$configPath}\n");
        exit(2);
    }

    $decoded = json_decode($raw, true);
    if (!is_array($decoded)) {
        fwrite(STDERR, "Invalid JSON config: {$configPath}\n");
        exit(2);
    }

    if (!isset($decoded['rules']) || !is_array($decoded['rules'])) {
        fwrite(STDERR, "Config missing rules array\n");
        exit(2);
    }

    // Validate each rule has required fields and valid regex pattern
    foreach ($decoded['rules'] as $index => $rule) {
        if (!isset($rule['name']) || !is_string($rule['name']) || trim($rule['name']) === '') {
            fwrite(STDERR, "Rule #{$index} missing or invalid 'name' field\n");
            exit(2);
        }
        
        if (!isset($rule['pattern']) || !is_string($rule['pattern']) || trim($rule['pattern']) === '') {
            fwrite(STDERR, "Rule '{$rule['name']}' missing or invalid 'pattern' field\n");
            exit(2);
        }
        
        // Validate regex pattern to prevent ReDoS
        $testResult = @preg_match($rule['pattern'], '');
        if ($testResult === false) {
            fwrite(STDERR, "Rule '{$rule['name']}' has invalid regex pattern: {$rule['pattern']}\n");
            exit(2);
        }
    }

    if (!isset($decoded['actions']['onMatch']) || !is_array($decoded['actions']['onMatch'])) {
        fwrite(STDERR, "Config missing actions.onMatch array\n");
        exit(2);
    }

    if (!isset($decoded['actions']['onConnect']) || !is_array($decoded['actions']['onConnect'])) {
        fwrite(STDERR, "Config missing actions.onConnect array\n");
        exit(2);
    }

    if (!isset($decoded['actions']['onStartup']) || !is_array($decoded['actions']['onStartup'])) {
        fwrite(STDERR, "Config missing actions.onStartup array\n");
        exit(2);
    }

    if (!isset($decoded['actions']['onDebug']) || !is_array($decoded['actions']['onDebug'])) {
        fwrite(STDERR, "Config missing actions.onDebug array\n");
        exit(2);
    }

    if (!isset($decoded['actions']['onConnectMessage']) || !is_string($decoded['actions']['onConnectMessage']) || trim($decoded['actions']['onConnectMessage']) === '') {
        fwrite(STDERR, "Config missing actions.onConnectMessage string\n");
        exit(2);
    }

    if (!isset($decoded['admins']) || !is_array($decoded['admins'])) {
        fwrite(STDERR, "Config missing admins array\n");
        exit(2);
    }

    if (!isset($decoded['retry']['maxAttempts']) || !is_int($decoded['retry']['maxAttempts'])) {
        fwrite(STDERR, "Config missing retry.maxAttempts integer\n");
        exit(2);
    }

    if (!isset($decoded['retry']['delaysMs']) || !is_array($decoded['retry']['delaysMs'])) {
        fwrite(STDERR, "Config missing retry.delaysMs array\n");
        exit(2);
    }

    $decoded['cacheTtlSeconds'] = isset($decoded['cacheTtlSeconds']) && is_int($decoded['cacheTtlSeconds'])
        ? $decoded['cacheTtlSeconds']
        : 1800;

    $decoded['dedupeWindowSeconds'] = isset($decoded['dedupeWindowSeconds']) && is_int($decoded['dedupeWindowSeconds'])
        ? $decoded['dedupeWindowSeconds']
        : 15;

    $decoded['ipInfoTimeoutSeconds'] = isset($decoded['ipInfoTimeoutSeconds']) && is_int($decoded['ipInfoTimeoutSeconds'])
        ? $decoded['ipInfoTimeoutSeconds']
        : 2;

    $decoded['ipInfoRateLimitPerMinute'] = isset($decoded['ipInfoRateLimitPerMinute']) && is_int($decoded['ipInfoRateLimitPerMinute'])
        ? $decoded['ipInfoRateLimitPerMinute']
        : 30;

    $decoded['metricsIntervalSeconds'] = isset($decoded['metricsIntervalSeconds']) && is_int($decoded['metricsIntervalSeconds'])
        ? $decoded['metricsIntervalSeconds']
        : 0;

    $decoded['debug'] = isset($decoded['debug']) && is_bool($decoded['debug'])
        ? $decoded['debug']
        : false;

    $decoded['actions']['onMetrics'] = isset($decoded['actions']['onMetrics']) && is_array($decoded['actions']['onMetrics'])
        ? $decoded['actions']['onMetrics']
        : [];

    return $decoded;
}
