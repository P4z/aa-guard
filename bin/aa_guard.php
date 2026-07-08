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

$configPath = $argv[1] ?? (__DIR__ . '/../config');

try {
    $config = loadConfig($configPath);
} catch (\RuntimeException $e) {
    fwrite(STDERR, $e->getMessage() . "\n");
    exit(2);
}

$metrics = new Metrics();
$ipInfoToken = getenv('IPINFO_TOKEN');
$ipInfoClient = new IpInfoClient(
    $config['ipInfoBaseUrl'],
    is_string($ipInfoToken) ? $ipInfoToken : null,
    $config['ipInfoTimeoutSeconds'],
    $config['ipInfoRateLimitPerMinute'],
    $metrics
);
$actions = new ActionRegistry(static function (string $command): void {
    fwrite(STDOUT, $command . PHP_EOL);
    fflush(STDOUT);
});
// Forwarder is attached after $guard exists (see below) so it can filter to
// currently present admins instead of messaging everyone in the admin list.
$logger = new Logger();
$matcher = new Matcher($config['rules'], $logger);

// Reloads configuration from disk for `/guard reload` and SIGHUP. Must throw
// (never exit) on failure so Guard::reloadConfiguration() can keep the
// last-known-good config/matcher when the new config is invalid.
// NOTE: does not rebuild $ipInfoClient, so ipInfoTimeoutSeconds and
// ipInfoRateLimitPerMinute changes require a process restart to take effect.
$reloadConfig = static function () use ($configPath, $logger, &$config): array {
    $newConfig = loadConfig($configPath);
    // Keep $config in sync so the debug-forwarding closure below (which
    // captured $config by reference) picks up the new onDebug/debug
    // settings too, not just Guard's own GuardConfig/Matcher. Admin presence
    // for the forwarder comes from $guard's own (also reloaded) config instead.
    $config = $newConfig;

    return [
        'config' => buildGuardConfig($newConfig),
        'matcher' => new Matcher($newConfig['rules'], $logger),
    ];
};

$guard = new Guard(
    $ipInfoClient,
    $matcher,
    $actions,
    $logger,
    buildGuardConfig($config),
    $metrics,
    $reloadConfig
);

// Only forward debug logs to admins currently tracked as online, matching
// the presence filtering already applied to onConnect/onMetrics/reload output.
$logger->setLogForwarder(
    static function (string $level, string $message) use (&$config, $actions, $guard): void {
        if (($config['debug'] ?? false) !== true) {
            return;
        }

        foreach ($guard->getPresentAdminRecipients() as $admin) {
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

stream_set_blocking(STDIN, false);
$actions->executeTemplates($config['actions']['onStartup'], []);
$logger->debug('AA guard started');

$running = true;
$reportMetricsPending = false;
$reloadConfigPending = false;
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
    pcntl_signal(SIGHUP, static function () use (&$reloadConfigPending): void {
        $reloadConfigPending = true;
    });
}

$lastMetricsAt = microtime(true);

while ($running) {
    $read = [STDIN];
    $write = [];
    $except = [];

    $result = @stream_select($read, $write, $except, 0, STREAM_SELECT_INTERVAL_US);
    if ($result === false) {
        // With pcntl_async_signals enabled, any delivered signal (SIGTERM,
        // SIGINT, SIGUSR1, SIGHUP) interrupts a blocking stream_select with
        // EINTR, which PHP also reports as a warning (suppressed above).
        // This is expected, not an I/O failure: the signal handler already
        // ran and updated its flag, so just retry the select on the next
        // iteration instead of tearing down the guard.
        continue;
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

    if ($reloadConfigPending) {
        $guard->reloadConfigurationForAllAdmins();
        $reloadConfigPending = false;
    }

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
    if (is_dir($configPath)) {
        $decoded = loadSplitConfig($configPath);
    } else {
        $decoded = loadJsonFile($configPath, 'Config file');
    }

    if (!isset($decoded['rules']) || !is_array($decoded['rules'])) {
        throw new \RuntimeException('Config missing rules array');
    }

    // Validate each rule has required fields and valid regex pattern
    foreach ($decoded['rules'] as $index => $rule) {
        if (!isset($rule['name']) || !is_string($rule['name']) || trim($rule['name']) === '') {
            throw new \RuntimeException("Rule #{$index} missing or invalid 'name' field");
        }
        
        if (!isset($rule['pattern']) || !is_string($rule['pattern']) || trim($rule['pattern']) === '') {
            throw new \RuntimeException("Rule '{$rule['name']}' missing or invalid 'pattern' field");
        }
        
        // Validate regex pattern to prevent ReDoS
        $testResult = @preg_match($rule['pattern'], '');
        if ($testResult === false) {
            throw new \RuntimeException("Rule '{$rule['name']}' has invalid regex pattern: {$rule['pattern']}");
        }
    }

    if (!isset($decoded['actions']['onMatch']) || !is_array($decoded['actions']['onMatch'])) {
        throw new \RuntimeException('Config missing actions.onMatch array');
    }

    if (!isset($decoded['actions']['onConnect']) || !is_array($decoded['actions']['onConnect'])) {
        throw new \RuntimeException('Config missing actions.onConnect array');
    }

    if (!isset($decoded['actions']['onStartup']) || !is_array($decoded['actions']['onStartup'])) {
        throw new \RuntimeException('Config missing actions.onStartup array');
    }

    if (!isset($decoded['actions']['onDebug']) || !is_array($decoded['actions']['onDebug'])) {
        throw new \RuntimeException('Config missing actions.onDebug array');
    }

    if (!isset($decoded['actions']['onConnectMessage']) || !is_string($decoded['actions']['onConnectMessage']) || trim($decoded['actions']['onConnectMessage']) === '') {
        throw new \RuntimeException('Config missing actions.onConnectMessage string');
    }

    if (!isset($decoded['admins']) || !is_array($decoded['admins'])) {
        throw new \RuntimeException('Config missing admins array');
    }

    if (!isset($decoded['retry']['maxAttempts']) || !is_int($decoded['retry']['maxAttempts'])) {
        throw new \RuntimeException('Config missing retry.maxAttempts integer');
    }

    if (!isset($decoded['retry']['delaysMs']) || !is_array($decoded['retry']['delaysMs'])) {
        throw new \RuntimeException('Config missing retry.delaysMs array');
    }

    $decoded['cacheTtlSeconds'] = isset($decoded['cacheTtlSeconds']) && is_int($decoded['cacheTtlSeconds'])
        ? $decoded['cacheTtlSeconds']
        : 1800;

    $decoded['dedupeWindowSeconds'] = isset($decoded['dedupeWindowSeconds']) && is_int($decoded['dedupeWindowSeconds'])
        ? $decoded['dedupeWindowSeconds']
        : 15;

    $decoded['ipInfoBaseUrl'] = isset($decoded['ipInfoBaseUrl']) && is_string($decoded['ipInfoBaseUrl']) && trim($decoded['ipInfoBaseUrl']) !== ''
        ? trim($decoded['ipInfoBaseUrl'])
        : 'https://ipinfo.io';

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

    $decoded['actions']['onErrorMessage'] = isset($decoded['actions']['onErrorMessage']) && is_array($decoded['actions']['onErrorMessage'])
        ? $decoded['actions']['onErrorMessage']
        : [];

    $decoded['actions']['onError'] = isset($decoded['actions']['onError']) && is_array($decoded['actions']['onError'])
        ? $decoded['actions']['onError']
        : [];

    return $decoded;
}

function loadSplitConfig(string $configDir): array
{
    $general = loadJsonFile($configDir . '/general.json', 'Config file');
    $actions = loadJsonFile($configDir . '/actions.json', 'Config file');
    $rules = loadJsonFile($configDir . '/rules.json', 'Config file');

    if (!isset($general['actions']) || !is_array($general['actions'])) {
        $general['actions'] = [];
    }

    $general['actions'] = array_merge($general['actions'], $actions);
    $general['rules'] = $rules;

    return $general;
}

function loadJsonFile(string $path, string $label): array
{
    if (!is_file($path)) {
        throw new \RuntimeException("{$label} not found: {$path}");
    }

    $raw = file_get_contents($path);
    if ($raw === false) {
        throw new \RuntimeException("Failed to read {$label}: {$path}");
    }

    $decoded = json_decode($raw, true);
    if (!is_array($decoded)) {
        throw new \RuntimeException("Invalid JSON in {$label}: {$path}");
    }

    return $decoded;
}

function buildGuardConfig(array $config): GuardConfig
{
    return new GuardConfig(
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
        onErrorQuotes:       $config['actions']['onErrorMessage'],
        onErrorActions:      $config['actions']['onError'],
    );
}
