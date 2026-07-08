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

// Shell metacharacters must be PRESERVED. The guard writes directly to a file handle —
// no shell is involved — so ; $ | ` & ( are harmless and may appear in player names
// (e.g. "$+3\@|+#"). Only actual control chars (0x00-0x1F, 0x7F) are stripped because
// they can split the line and inject a second command.
$dangerousInputs = [
    'player_id' => 'hacker; rm -rf /',
    'display_name' => 'evil$(whoami)',
    'ip' => '1.2.3.4|cat /etc/passwd',
    'network_name' => 'VPN`id`',
    'country' => 'US&& curl evil.com',
];

$commands = [];
$registry->executeTemplates(['KICK {{player_id}} {{display_name}} {{ip}} {{network_name}} {{country}}'], $dangerousInputs);

$test->assertEquals(1, count($commands), "Executes one command");
$command = $commands[0];

$test->assertContains(';', $command, "Preserves semicolon (no shell involved)");
$test->assertContains('$', $command, "Preserves dollar sign");
$test->assertContains('|', $command, "Preserves pipe");
$test->assertContains('`', $command, "Preserves backtick");
$test->assertContains('&', $command, "Preserves ampersand");
$test->assertContains('(', $command, "Preserves parenthesis");

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

// Clan-tag braces and other exotic but printable nickname chars
$braceInputs = ['player_id' => '{mtp}stabber'];
$commands = [];
$registry->executeTemplates(['KICK {{player_id}}'], $braceInputs);
$command = $commands[0];
$test->assertContains('{mtp}stabber', $command, "Preserves clan-tag braces in player ID");

// Unicode, accented chars, and exotic punctuation found in real player names
$nicknameInputs = ['player_id' => '$+3\\@|+# ├│ ^* </s>'];
$commands = [];
$registry->executeTemplates(['KICK 0xffffff{{player_id}}'], $nicknameInputs);
$command = $commands[0];
$test->assertContains('$+3\\@|+# ├│ ^* </s>', $command, "Preserves unicode and exotic nickname chars");

// Actual newline in a player name would split the emitted line into two commands.
// It must be stripped.
$commands = [];
$registry->executeTemplates(['KICK {{player_id}}'], ['player_id' => "hacker\ncmd_injected"]);
$test->assertEquals(1, count($commands), "Newline removal still yields one command");
$command = $commands[0];
$test->assertNotContains("\n", $command, "Strips actual newline (prevents command injection)");
$test->assertContains('hacker', $command, "Keeps text before stripped newline");

// Literal backslash-n in player name (two printable chars) must NOT be treated as newline
$commands = [];
$registry->executeTemplates(['KICK {{player_id}}'], ['player_id' => 'player\\nname']);
$command = $commands[0];
$test->assertContains('player\\nname', $command, "Literal backslash-n preserved, not treated as newline");

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

// localTimeForTimezone(): valid IANA timezone computes real local time for that zone
$localTimeForTimezoneMethod = $reflection->getMethod('localTimeForTimezone');
$localTimeForTimezoneMethod->setAccessible(true);
$tokyoTime = $localTimeForTimezoneMethod->invoke($guard, 'Asia/Tokyo');
$expectedTokyoTime = (new DateTimeImmutable('now', new DateTimeZone('Asia/Tokyo')))->format('H:i');
$test->assertEquals($expectedTokyoTime, $tokyoTime, "localTimeForTimezone() computes real local time for a valid IANA timezone");

// localTimeForTimezone(): invalid/unknown timezone reports 'unknown', no server-time fallback
$unknownForInvalidTz = $localTimeForTimezoneMethod->invoke($guard, 'Not/AZone');
$test->assertEquals('unknown', $unknownForInvalidTz, "localTimeForTimezone() reports 'unknown' for invalid timezone string");

// localTimeForTimezone(): null timezone (lookup failed / unknown) reports 'unknown', no server-time fallback
$unknownForNullTz = $localTimeForTimezoneMethod->invoke($guard, null);
$test->assertEquals('unknown', $unknownForNullTz, "localTimeForTimezone() reports 'unknown' when timezone is null");

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

$parsePlayerRenamed = $reflection->getMethod('parsePlayerRenamed');
$parsePlayerRenamed->setAccessible(true);
$renamed = $parsePlayerRenamed->invoke($guard, 'PLAYER_RENAMED vanbozo vanbozo@rcl 192.168.51.69 1 vanbozo');
$test->assertEquals(true, is_array($renamed), 'Parses PLAYER_RENAMED line');
$test->assertEquals('vanbozo', $renamed['oldPlayerId'] ?? null, 'Extracts old player id from PLAYER_RENAMED');
$test->assertEquals('vanbozo@rcl', $renamed['newPlayerId'] ?? null, 'Extracts new player id from PLAYER_RENAMED');
$test->assertEquals('192.168.51.69', $renamed['ip'] ?? null, 'Extracts IP from PLAYER_RENAMED');
$test->assertEquals(true, $renamed['didLogin'] ?? null, 'Extracts did_login flag from PLAYER_RENAMED');
$test->assertEquals('vanbozo', $renamed['displayName'] ?? null, 'Extracts screen name from PLAYER_RENAMED');

$parsePlayerEnteredSpectator = $reflection->getMethod('parsePlayerEnteredSpectator');
$parsePlayerEnteredSpectator->setAccessible(true);
$spectator = $parsePlayerEnteredSpectator->invoke($guard, 'PLAYER_ENTERED_SPECTATOR spectator_p4 192.168.51.69 P4');
$test->assertEquals(true, is_array($spectator), 'Parses PLAYER_ENTERED_SPECTATOR line');
$test->assertEquals('spectator_p4', $spectator['playerId'] ?? null, 'Extracts player id from PLAYER_ENTERED_SPECTATOR');
$test->assertEquals('192.168.51.69', $spectator['ip'] ?? null, 'Extracts IP from PLAYER_ENTERED_SPECTATOR');
$test->assertEquals('P4', $spectator['displayName'] ?? null, 'Extracts display name from PLAYER_ENTERED_SPECTATOR');
$test->assertEquals(true, is_array($parsePlayerEnteredSpectator->invoke($guard, 'PLAYER_ENTERED_SPECTATOR s1 8.8.8.8 Spectator One')), 'Accepts valid spectator entry');

foreach (['999.999.999.999', 'not-an-ip'] as $invalidIp) {
    $result = $parsePlayerEnteredSpectator->invoke($guard, "PLAYER_ENTERED_SPECTATOR s1 {$invalidIp} Spec");
    $test->assertEquals(null, $result, "Rejects invalid IP in PLAYER_ENTERED_SPECTATOR: {$invalidIp}");
}

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
$test->assert(in_array('LADDERLOG_WRITE_PLAYER_ENTERED_GRID 1', $actionsConfig['onStartup'] ?? [], true), 'Startup actions enable PLAYER_ENTERED_GRID ladderlog writes');
$test->assert(in_array('LADDERLOG_WRITE_PLAYER_ENTERED_SPECTATOR 1', $actionsConfig['onStartup'] ?? [], true), 'Startup actions enable PLAYER_ENTERED_SPECTATOR ladderlog writes');
$test->assert(in_array('LADDERLOG_WRITE_INVALID_COMMAND 1', $actionsConfig['onStartup'] ?? [], true), 'Startup actions enable INVALID_COMMAND ladderlog writes');
$test->assert(in_array('LADDERLOG_WRITE_PLAYER_RENAMED 1', $actionsConfig['onStartup'] ?? [], true), 'Startup actions enable PLAYER_RENAMED ladderlog writes');
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
            '# CONSOLE_MESSAGE {{player_id}} is connecting from {{country_name}} ({{country_code}}), network: {{network_name}}. time={{time}}',
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
        'timezone' => 'Europe/Warsaw',
        'expiresAt' => microtime(true) + 60,
    ],
]);

$connectOnlinePlayersProperty = $guardReflection->getProperty('onlinePlayers');
$connectOnlinePlayersProperty->setAccessible(true);
$connectOnlinePlayersProperty->setValue($guardForConnect, [
    'AdminOne' => ['player_id' => 'AdminOne', 'player_name' => 'AdminOne', 'player_ip' => '1.2.3.4', 'player_country' => 'unknown', 'player_network' => 'unknown', 'player_timezone' => null],
]);

$guardForConnect->handleLogLine('PLAYER_ENTERED_GRID player_one 8.8.8.8 Player One');

$test->assertEquals(2, count($onConnectCommands), "onConnect emits console and admin messages");
$test->assertContains('Poland (PL)', $onConnectCommands[0] ?? '', "CONSOLE_MESSAGE includes full country name and code");
$test->assertContains('Orange Polska S.A.', $onConnectCommands[0] ?? '', "CONSOLE_MESSAGE includes as-name/network");
$test->assert(preg_match('/time=\d{2}:\d{2}/', $onConnectCommands[0] ?? '') === 1, "CONSOLE_MESSAGE includes {{time}} placeholder rendered as HH:MM");
$expectedWarsawTime = (new DateTimeImmutable('now', new DateTimeZone('Europe/Warsaw')))->format('H:i');
$test->assertContains('time=' . $expectedWarsawTime, $onConnectCommands[0] ?? '', "join {{time}} uses player's own timezone (Europe/Warsaw) from ipinfo.io, not server local time");
$test->assertContains('Poland (PL)', $onConnectCommands[1] ?? '', "PLAYER_MESSAGE includes full country name and code");
$test->assertContains('Orange Polska S.A.', $onConnectCommands[1] ?? '', "PLAYER_MESSAGE includes as-name/network");

$noTzCommands = [];
$noTzRegistry = new ActionRegistry(function (string $command) use (&$noTzCommands): void {
    $noTzCommands[] = $command;
});

$guardForNoTimezone = new Guard(
    new IpInfoClient('https://ipinfo.io', null, 2),
    new Matcher([['name' => 'never-match', 'pattern' => '/^$/']]),
    $noTzRegistry,
    new Logger(),
    new GuardConfig(
        adminRecipients: ['AdminOne'],
        onConnectMessageTemplate: '{{player_id}} is connecting from {{country_name}} ({{country_code}}), network: {{network_name}}, time={{time}}.',
        onConnectActions: ['PLAYER_MESSAGE {{admin}} "{{msg}}"'],
        onMatchActions: [],
        retryDelaysMs: [100],
        maxAttempts: 1,
        cacheTtlSeconds: 1800,
        dedupeWindowSeconds: 15,
    ),
    new Metrics()
);

$noTzReflection = new ReflectionClass($guardForNoTimezone);
$noTzCacheProperty = $noTzReflection->getProperty('ipCache');
$noTzCacheProperty->setAccessible(true);
$noTzCacheProperty->setValue($guardForNoTimezone, [
    '9.9.9.9' => [
        'networkName' => 'Unknown Provider',
        'country' => 'Poland',
        'countryCode' => 'PL',
        'countryName' => 'Poland',
        'timezone' => null,
        'expiresAt' => microtime(true) + 60,
    ],
]);

$noTzOnlinePlayersProperty = $noTzReflection->getProperty('onlinePlayers');
$noTzOnlinePlayersProperty->setAccessible(true);
$noTzOnlinePlayersProperty->setValue($guardForNoTimezone, [
    'AdminOne' => ['player_id' => 'AdminOne', 'player_name' => 'AdminOne', 'player_ip' => '1.2.3.4', 'player_country' => 'unknown', 'player_network' => 'unknown', 'player_timezone' => null],
]);

$guardForNoTimezone->handleLogLine('PLAYER_ENTERED_GRID player_no_tz 9.9.9.9 Player NoTZ');

$test->assertEquals(1, count($noTzCommands), "onConnect emits admin message even without timezone data");
$test->assertContains('time=unknown', $noTzCommands[0] ?? '', "join {{time}} shows 'unknown' (not server clock) when ipinfo.io provides no timezone");

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

$multiOnlinePlayersProperty = $multiGuardReflection->getProperty('onlinePlayers');
$multiOnlinePlayersProperty->setAccessible(true);
$multiOnlinePlayersProperty->setValue($guardForMultiAdmin, [
    'AdminOne' => ['player_id' => 'AdminOne', 'player_name' => 'AdminOne', 'player_ip' => '5.5.5.5', 'player_country' => 'unknown', 'player_network' => 'unknown', 'player_timezone' => null],
    'AdminTwo' => ['player_id' => 'AdminTwo', 'player_name' => 'AdminTwo', 'player_ip' => '6.6.6.6', 'player_country' => 'unknown', 'player_network' => 'unknown', 'player_timezone' => null],
]);

$guardForMultiAdmin->handleLogLine('PLAYER_ENTERED_GRID player_two 1.1.1.1 Player Two');

$test->assertEquals(3, count($multiAdminCommands), "One console message and two admin messages are emitted for two present admins");
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
            onMetricsActions:    ['PLAYER_MESSAGE {{admin}} "bans={{bans}} lookups={{lookups}} cacheSize={{cache_size}} invalidIps={{invalid_ips}} runtime={{runtime}}"'],
            onErrorQuotes:       ['TEST_ERROR_QUOTE'],
            onErrorActions:      ['PLAYER_MESSAGE {{player_id}} "{{msg}}"'],
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
$internalAdminReflection = new ReflectionClass($internalAdminGuard);
$internalAdminCacheProperty = $internalAdminReflection->getProperty('ipCache');
$internalAdminCacheProperty->setAccessible(true);
$internalAdminCacheProperty->setValue($internalAdminGuard, [
    '8.8.8.8' => [
        'networkName' => 'ExampleNet',
        'country' => 'US',
        'countryCode' => 'US',
        'countryName' => 'United States',
        'expiresAt' => microtime(true) + 60,
    ],
]);
$buildMetricsLogStringMethod = $internalAdminReflection->getMethod('buildMetricsLogString');
$buildMetricsLogStringMethod->setAccessible(true);
$test->assertContains('cache_size=1', $buildMetricsLogStringMethod->invoke($internalAdminGuard), 'Metrics debug log includes live cache size');
$internalAdminGuard->handleLogLine('INVALID_COMMAND guard internal_admin 8.8.8.8 0 metrics');

$test->assertEquals(1, count($internalAdminCommands), 'Internal admin metrics request emits one command');
$test->assertContains('PLAYER_MESSAGE internal_admin', $internalAdminCommands[0] ?? '', 'Internal admin metrics target the requester');
$test->assertNotContains('other_admin', $internalAdminCommands[0] ?? '', 'Internal admin metrics do not target other admins');
$test->assertContains('bans=3', $internalAdminCommands[0] ?? '', 'Internal admin metrics include counters');
$test->assertContains('cacheSize=1', $internalAdminCommands[0] ?? '', 'Internal admin metrics include live cache size');

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
$test->assertEquals(1, count($unauthorizedCommands), 'Unauthorized remote metrics request gets a private onError reply');
$test->assertContains('PLAYER_MESSAGE regular_user', $unauthorizedCommands[0] ?? '', 'Unauthorized onError reply targets the requester');
$test->assertContains('TEST_ERROR_QUOTE', $unauthorizedCommands[0] ?? '', 'Unauthorized onError reply includes configured quote');

$unknownRemoteMetrics = new Metrics();
$unknownRemoteCommands = [];
$unknownRemoteGuard = $buildGuardForRemoteCommandTest(['internal_admin'], $unknownRemoteCommands, $unknownRemoteMetrics);
$unknownRemoteGuard->handleLogLine('INVALID_COMMAND guard internal_admin 8.8.8.8 2 status');
$test->assertEquals(1, count($unknownRemoteCommands), 'Unknown remote guard subcommand gets a private onError reply');
$test->assertContains('PLAYER_MESSAGE internal_admin', $unknownRemoteCommands[0] ?? '', 'Unknown-subcommand onError reply targets the requester');
$test->assertContains('TEST_ERROR_QUOTE', $unknownRemoteCommands[0] ?? '', 'Unknown-subcommand onError reply includes configured quote');

$bareGuardMetrics = new Metrics();
$bareGuardCommands = [];
$bareGuardGuard = $buildGuardForRemoteCommandTest(['internal_admin'], $bareGuardCommands, $bareGuardMetrics);
$bareGuardGuard->handleLogLine('INVALID_COMMAND guard internal_admin 8.8.8.8 2');
$test->assertEquals(1, count($bareGuardCommands), 'Bare /guard with no subcommand gets a private onError reply');
$test->assertContains('PLAYER_MESSAGE internal_admin', $bareGuardCommands[0] ?? '', 'Bare /guard onError reply targets the requester');
$test->assertContains('TEST_ERROR_QUOTE', $bareGuardCommands[0] ?? '', 'Bare /guard onError reply includes configured quote');

$noQuotesConfigured = [];
$noQuotesMetrics = new Metrics();
$noQuotesActionRegistry = new ActionRegistry(function (string $command) use (&$noQuotesConfigured): void {
    $noQuotesConfigured[] = $command;
});
$noQuotesGuard = new Guard(
    new IpInfoClient('https://ipinfo.io', null, 2, 0, $noQuotesMetrics),
    new Matcher([]),
    $noQuotesActionRegistry,
    new Logger(),
    new GuardConfig(
        adminRecipients:     ['internal_admin'],
        onConnectMessageTemplate: '{{player_id}} joined from {{country_name}}',
        onConnectActions:    [],
        onMatchActions:      [],
        retryDelaysMs:       [100],
        maxAttempts:         1,
        cacheTtlSeconds:     60,
        dedupeWindowSeconds: 15,
    ),
    $noQuotesMetrics
);
$noQuotesGuard->handleLogLine('INVALID_COMMAND guard internal_admin 8.8.8.8 2 status');
$test->assertEquals(0, count($noQuotesConfigured), 'Unknown subcommand stays silent when onError is unconfigured');

$quotesOnlyConfigured = [];
$quotesOnlyMetrics = new Metrics();
$quotesOnlyActionRegistry = new ActionRegistry(function (string $command) use (&$quotesOnlyConfigured): void {
    $quotesOnlyConfigured[] = $command;
});
$quotesOnlyGuard = new Guard(
    new IpInfoClient('https://ipinfo.io', null, 2, 0, $quotesOnlyMetrics),
    new Matcher([]),
    $quotesOnlyActionRegistry,
    new Logger(),
    new GuardConfig(
        adminRecipients:     ['internal_admin'],
        onConnectMessageTemplate: '{{player_id}} joined from {{country_name}}',
        onConnectActions:    [],
        onMatchActions:      [],
        retryDelaysMs:       [100],
        maxAttempts:         1,
        cacheTtlSeconds:     60,
        dedupeWindowSeconds: 15,
        onErrorQuotes:       ['TEST_ERROR_QUOTE'],
    ),
    $quotesOnlyMetrics
);
$quotesOnlyGuard->handleLogLine('INVALID_COMMAND guard internal_admin 8.8.8.8 2 status');
$test->assertEquals(0, count($quotesOnlyConfigured), 'Unknown subcommand stays silent when onErrorMessage is configured but onError actions are not');

$presentAdminMetrics = new Metrics();
$presentAdminCommands = [];
$presentAdminGuard = $buildGuardForRemoteCommandTest(['admin_online', 'admin_offline'], $presentAdminCommands, $presentAdminMetrics);
$presentAdminReflection = new ReflectionClass($presentAdminGuard);
$presentOnlinePlayersProperty = $presentAdminReflection->getProperty('onlinePlayers');
$presentOnlinePlayersProperty->setAccessible(true);
$presentOnlinePlayersProperty->setValue($presentAdminGuard, [
    'admin_online' => [
        'player_id' => 'admin_online',
        'player_name' => 'Admin Online',
        'player_ip' => '8.8.8.8',
        'player_country' => 'United States',
        'player_network' => 'Example ISP',
    ],
    'regular_user' => [
        'player_id' => 'regular_user',
        'player_name' => 'Regular User',
        'player_ip' => '9.9.9.9',
        'player_country' => 'United States',
        'player_network' => 'Another ISP',
    ],
]);

$presentAdminGuard->reportMetrics();
$test->assertEquals(1, count($presentAdminCommands), 'Periodic metrics emit only to present admins');
$test->assertContains('PLAYER_MESSAGE admin_online', $presentAdminCommands[0] ?? '', 'Periodic metrics target present admin');
$test->assertNotContains('admin_offline', $presentAdminCommands[0] ?? '', 'Periodic metrics skip absent admin');

$absentAdminMetrics = new Metrics();
$absentAdminCommands = [];
$absentAdminGuard = $buildGuardForRemoteCommandTest(['admin_offline'], $absentAdminCommands, $absentAdminMetrics);
$absentAdminReflection = new ReflectionClass($absentAdminGuard);
$absentOnlinePlayersProperty = $absentAdminReflection->getProperty('onlinePlayers');
$absentOnlinePlayersProperty->setAccessible(true);
$absentOnlinePlayersProperty->setValue($absentAdminGuard, []);

$absentAdminGuard->reportMetrics();
$test->assertEquals(0, count($absentAdminCommands), 'Periodic metrics emit nothing when no admin is present');

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
        'timezone' => 'America/Los_Angeles',
        'expiresAt' => microtime(true) + 60,
    ],
]);

$playersGuard->handleLogLine('PLAYER_ENTERED_GRID player_1 8.8.8.8 Player One');
$playersGuard->handleLogLine('INVALID_COMMAND guard internal_admin 8.8.8.8 2 players');

$playerListCommands = array_values(array_filter(
    $playersCommands,
    static fn (string $command): bool => str_contains($command, 'id=0xffff00player_1')
));

$test->assertEquals(1, count($playerListCommands), 'Remote players command emits one line per tracked player');
$test->assertContains('PLAYER_MESSAGE internal_admin', $playerListCommands[0] ?? '', 'Remote players response targets requester only');
$test->assertContains('name=0xffff00Player One', $playerListCommands[0] ?? '', 'Remote players response includes player_name');
$test->assertContains('country=0xffff00United States', $playerListCommands[0] ?? '', 'Remote players response includes player_country');
$test->assertContains('network=0xffff00Example ISP', $playerListCommands[0] ?? '', 'Remote players response includes player_network');
$test->assert(preg_match('/time=0xffff00\d{2}:\d{2}/', $playerListCommands[0] ?? '') === 1, 'Remote players response includes time field in HH:MM format');

$expectedLosAngelesTime = (new DateTimeImmutable('now', new DateTimeZone('America/Los_Angeles')))->format('H:i');
$test->assertContains('time=0xffff00' . $expectedLosAngelesTime, $playerListCommands[0] ?? '', 'Remote players response uses player\'s own timezone (America/Los_Angeles), not server local time');

$playersCommands = [];
$playersGuard->handleLogLine('PLAYER_LEFT player_1 8.8.8.8 Player One');
$playersGuard->handleLogLine('INVALID_COMMAND guard internal_admin 8.8.8.8 2 players');

$test->assertEquals(1, count($playersCommands), 'Remote players command emits one response when list is empty');
$test->assertContains('No tracked players online.', $playersCommands[0] ?? '', 'Remote players command reports empty tracked list after PLAYER_LEFT');

$playersCommands = [];
$playersGuard->handleLogLine('PLAYER_ENTERED_GRID vanbozo 8.8.8.8 vanbozo');
$playersGuard->handleLogLine('PLAYER_RENAMED vanbozo vanbozo@rcl 192.168.51.69 1 vanbozo');
$playersGuard->handleLogLine('INVALID_COMMAND guard internal_admin 8.8.8.8 2 players');

$renamedPlayerListCommands = array_values(array_filter(
    $playersCommands,
    static fn (string $command): bool => str_contains($command, 'id=0xffff00')
));

$test->assertEquals(1, count($renamedPlayerListCommands), 'Remote players command emits one list row for renamed player');
$test->assertContains('id=0xffff00vanbozo@rcl', $renamedPlayerListCommands[0] ?? '', 'Remote players response uses renamed player id');
$test->assertContains('name=0xffff00vanbozo', $renamedPlayerListCommands[0] ?? '', 'Remote players response keeps screen name after rename');
$test->assertNotContains('id=0xffff00vanbozo 0xffffff', $renamedPlayerListCommands[0] ?? '', 'Remote players response does not include old player id after rename');

// Test spectator and grid players together using fresh Guard instance
$spectatorMetrics = new Metrics();
$spectatorCommands = [];
$spectatorGuard = $buildGuardForRemoteCommandTest(['internal_admin'], $spectatorCommands, $spectatorMetrics);
$spectatorReflection = new ReflectionClass($spectatorGuard);
$spectatorCacheProperty = $spectatorReflection->getProperty('ipCache');
$spectatorCacheProperty->setAccessible(true);
$spectatorCacheProperty->setValue($spectatorGuard, [
    '1.1.1.1' => [
        'networkName' => 'Example ISP',
        'country' => 'United States',
        'countryCode' => 'US',
        'countryName' => 'United States',
        'expiresAt' => microtime(true) + 60,
    ],
    '2.2.2.2' => [
        'networkName' => 'Another ISP',
        'country' => 'United Kingdom',
        'countryCode' => 'UK',
        'countryName' => 'United Kingdom',
        'expiresAt' => microtime(true) + 60,
    ],
]);

$spectatorGuard->handleLogLine('PLAYER_ENTERED_GRID player_grid 1.1.1.1 Player Grid');
$spectatorGuard->handleLogLine('PLAYER_ENTERED_SPECTATOR spectator_one 2.2.2.2 Spectator One');
$spectatorGuard->handleLogLine('INVALID_COMMAND guard internal_admin 8.8.8.8 2 players');

$playerListRows = array_values(array_filter(
    $spectatorCommands,
    static fn (string $command): bool => str_contains($command, 'id=0xffff00')
));

$test->assertEquals(2, count($playerListRows), 'Remote players command lists both grid and spectator entries');
$test->assertContains('id=0xffff00player_grid', $playerListRows[0] ?? '', 'Remote players response includes grid player');
$test->assertContains('id=0xffff00spectator_one', $playerListRows[1] ?? '', 'Remote players response includes spectator');
$test->assertContains('Player Grid', $playerListRows[0] ?? '', 'Remote players response includes grid player display name');
$test->assertContains('Spectator One', $playerListRows[1] ?? '', 'Remote players response includes spectator display name');

$remoteJoinMetrics = new Metrics();
$remoteJoinCommands = [];
$remoteJoinGuard = $buildGuardForRemoteCommandTest(['internal_admin'], $remoteJoinCommands, $remoteJoinMetrics);

$remoteJoinReflection = new ReflectionClass($remoteJoinGuard);
$remoteJoinOnlinePlayersProperty = $remoteJoinReflection->getProperty('onlinePlayers');
$remoteJoinOnlinePlayersProperty->setAccessible(true);
$remoteJoinOnlinePlayersProperty->setValue($remoteJoinGuard, [
    'internal_admin' => ['player_id' => 'internal_admin', 'player_name' => 'internal_admin', 'player_ip' => '7.7.7.7', 'player_country' => 'unknown', 'player_network' => 'unknown', 'player_timezone' => null],
]);

$remoteJoinGuard->handleLogLine('PLAYER_ENTERED_GRID player_three 8.8.8.8 Player Three');
$test->assert(count($remoteJoinCommands) >= 1, 'PLAYER_ENTERED_GRID handling still works alongside remote commands');
$test->assertContains('PLAYER_MESSAGE internal_admin', $remoteJoinCommands[0] ?? '', 'Join handling still emits admin-targeted connect message to present admin');

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

// Before fix this case emitted 0 admin messages. Now it must emit one per present admin.
$commandsMissingAdminTemplate = [];
$guardMissingAdminTemplate = $buildGuardForJoinTest(['CONSOLE_MESSAGE {{msg}}'], $commandsMissingAdminTemplate);
$missingAdminTemplateReflection = new ReflectionClass($guardMissingAdminTemplate);
$missingAdminTemplateOnlineProperty = $missingAdminTemplateReflection->getProperty('onlinePlayers');
$missingAdminTemplateOnlineProperty->setAccessible(true);
$missingAdminTemplateOnlineProperty->setValue($guardMissingAdminTemplate, [
    'admin_1' => ['player_id' => 'admin_1', 'player_name' => 'admin_1', 'player_ip' => '3.3.3.3', 'player_country' => 'unknown', 'player_network' => 'unknown', 'player_timezone' => null],
    'admin_2' => ['player_id' => 'admin_2', 'player_name' => 'admin_2', 'player_ip' => '4.4.4.4', 'player_country' => 'unknown', 'player_network' => 'unknown', 'player_timezone' => null],
]);
$guardMissingAdminTemplate->handleLogLine('PLAYER_ENTERED_GRID p1 8.8.8.8 Player One');

$adminMessages = array_values(array_filter(
    $commandsMissingAdminTemplate,
    static fn (string $command): bool => str_starts_with($command, 'PLAYER_MESSAGE admin_')
));
$test->assertEquals(2, count($adminMessages), 'Emits fallback admin join message for each present admin when onConnect has no {{admin}} template');

// If config already has an admin-targeted template, fallback must not duplicate it.
$commandsWithAdminTemplate = [];
$guardWithAdminTemplate = $buildGuardForJoinTest(['PLAYER_MESSAGE {{admin}} "{{msg}}"'], $commandsWithAdminTemplate);
$withAdminTemplateReflection = new ReflectionClass($guardWithAdminTemplate);
$withAdminTemplateOnlineProperty = $withAdminTemplateReflection->getProperty('onlinePlayers');
$withAdminTemplateOnlineProperty->setAccessible(true);
$withAdminTemplateOnlineProperty->setValue($guardWithAdminTemplate, [
    'admin_1' => ['player_id' => 'admin_1', 'player_name' => 'admin_1', 'player_ip' => '3.3.3.3', 'player_country' => 'unknown', 'player_network' => 'unknown', 'player_timezone' => null],
    'admin_2' => ['player_id' => 'admin_2', 'player_name' => 'admin_2', 'player_ip' => '4.4.4.4', 'player_country' => 'unknown', 'player_network' => 'unknown', 'player_timezone' => null],
]);
$guardWithAdminTemplate->handleLogLine('PLAYER_ENTERED_GRID p2 1.1.1.1 Player Two');

$adminMessagesWithTemplate = array_values(array_filter(
    $commandsWithAdminTemplate,
    static fn (string $command): bool => str_starts_with($command, 'PLAYER_MESSAGE admin_')
));
$test->assertEquals(2, count($adminMessagesWithTemplate), 'Does not duplicate admin join message when {{admin}} template already exists');

// Regression test for reported bug: an {{admin}}-templated onConnect message must be
// sent ONLY to admins currently present (tracked online), never to absent admins.
$presenceCommands = [];
$guardForPresenceCheck = $buildGuardForJoinTest(['PLAYER_MESSAGE {{admin}} "{{msg}}"'], $presenceCommands);
$presenceReflection = new ReflectionClass($guardForPresenceCheck);
$presenceOnlineProperty = $presenceReflection->getProperty('onlinePlayers');
$presenceOnlineProperty->setAccessible(true);
// Only admin_1 is present (e.g. logged in); admin_2 is absent, mirroring the
// reported case where 'dplmr' was offline yet still received a PLAYER_MESSAGE.
$presenceOnlineProperty->setValue($guardForPresenceCheck, [
    'admin_1' => ['player_id' => 'admin_1', 'player_name' => 'admin_1', 'player_ip' => '3.3.3.3', 'player_country' => 'unknown', 'player_network' => 'unknown', 'player_timezone' => null],
]);
$guardForPresenceCheck->handleLogLine('PLAYER_ENTERED_GRID p3 8.8.8.8 Player Three');

$presentAdminMessages = array_values(array_filter(
    $presenceCommands,
    static fn (string $command): bool => str_starts_with($command, 'PLAYER_MESSAGE admin_')
));
$test->assertEquals(1, count($presentAdminMessages), 'Only present admins receive the {{admin}}-templated join message');
$test->assertContains('PLAYER_MESSAGE admin_1', $presentAdminMessages[0] ?? '', 'Present admin (admin_1) receives the join message');
$test->assertNotContains('admin_2', $presentAdminMessages[0] ?? '', 'Absent admin (admin_2) is not targeted');
foreach ($presenceCommands as $presenceCommand) {
    $test->assertNotContains('admin_2', $presenceCommand, 'Absent admin (admin_2) receives no command at all');
}

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
// Test 11: Remote command reload
// ===================================================================
echo "Test 11: Remote command reload\n";
echo str_repeat("-", 60) . "\n";

$buildGuardForReloadTest = function (array $adminRecipients, array &$emittedCommands, ?\Closure $configReloader): Guard {
    $emittedCommands = [];
    $actionRegistry = new ActionRegistry(function (string $command) use (&$emittedCommands): void {
        $emittedCommands[] = $command;
    });

    return new Guard(
        new IpInfoClient('https://ipinfo.io', null, 2, 0, new Metrics()),
        new Matcher([]),
        $actionRegistry,
        new Logger(),
        new GuardConfig(
            adminRecipients:     $adminRecipients,
            onConnectMessageTemplate: '{{player_id}} joined from {{country_name}}',
            onConnectActions:    [],
            onMatchActions:      [],
            retryDelaysMs:       [100],
            maxAttempts:         1,
            cacheTtlSeconds:     60,
            dedupeWindowSeconds: 15,
        ),
        new Metrics(),
        $configReloader
    );
};

// Matcher::getRuleCount() is used to report rule counts after reload.
$ruleCountMatcher = new Matcher([
    ['name' => 'a', 'pattern' => '/a/i'],
    ['name' => 'b', 'pattern' => '/b/i'],
]);
$test->assertEquals(2, $ruleCountMatcher->getRuleCount(), 'Matcher::getRuleCount() returns number of loaded rules');

// Successful reload swaps GuardConfig/Matcher and replies only to the requester.
$reloadSuccessCommands = [];
$newConfigAfterReload = new GuardConfig(
    adminRecipients:     ['internal_admin'],
    onConnectMessageTemplate: 'reloaded',
    onConnectActions:    [],
    onMatchActions:      [],
    retryDelaysMs:       [999],
    maxAttempts:         9,
    cacheTtlSeconds:     123,
    dedupeWindowSeconds: 5,
);
$newMatcherAfterReload = new Matcher([
    ['name' => 'vpn-test', 'pattern' => '/vpn/i'],
    ['name' => 'proxy-test', 'pattern' => '/proxy/i'],
]);
$reloadSuccessGuard = $buildGuardForReloadTest(['internal_admin'], $reloadSuccessCommands, function () use ($newConfigAfterReload, $newMatcherAfterReload): array {
    return ['config' => $newConfigAfterReload, 'matcher' => $newMatcherAfterReload];
});

$reloadSuccessGuard->handleLogLine('INVALID_COMMAND guard internal_admin 8.8.8.8 2 reload');

$test->assertEquals(1, count($reloadSuccessCommands), 'Successful reload emits one confirmation message');
$test->assertContains('PLAYER_MESSAGE internal_admin', $reloadSuccessCommands[0] ?? '', 'Reload confirmation targets the requester');
$test->assertContains('Configuration reloaded (0xffff002', $reloadSuccessCommands[0] ?? '', 'Reload confirmation reports the new rule count (2)');
$test->assertEquals(123, $reloadSuccessGuard->getConfig()->cacheTtlSeconds, 'GuardConfig is swapped in after successful reload');

// Failed reload (reloader throws) keeps the previous config/matcher untouched.
$reloadFailureCommands = [];
$reloadFailureGuard = $buildGuardForReloadTest(['internal_admin'], $reloadFailureCommands, function (): array {
    throw new \RuntimeException('Config missing rules array');
});
$originalCacheTtl = $reloadFailureGuard->getConfig()->cacheTtlSeconds;

$reloadFailureGuard->handleLogLine('INVALID_COMMAND guard internal_admin 8.8.8.8 2 reload');

$test->assertEquals(1, count($reloadFailureCommands), 'Failed reload emits one failure message');
$test->assertContains('PLAYER_MESSAGE internal_admin', $reloadFailureCommands[0] ?? '', 'Reload failure message targets the requester');
$test->assertContains('Config reload failed', $reloadFailureCommands[0] ?? '', 'Reload failure message states failure');
$test->assertContains('Config missing rules array', $reloadFailureCommands[0] ?? '', 'Reload failure message includes original error');
$test->assertEquals($originalCacheTtl, $reloadFailureGuard->getConfig()->cacheTtlSeconds, 'GuardConfig is left untouched after failed reload');

// No reloader configured: reload replies with a clear failure instead of crashing.
$reloadUnavailableCommands = [];
$reloadUnavailableGuard = $buildGuardForReloadTest(['internal_admin'], $reloadUnavailableCommands, null);
$reloadUnavailableGuard->handleLogLine('INVALID_COMMAND guard internal_admin 8.8.8.8 2 reload');

$test->assertEquals(1, count($reloadUnavailableCommands), 'Reload without a configured reloader still replies once');
$test->assertContains('Config reload failed', $reloadUnavailableCommands[0] ?? '', 'Reload without reloader reports failure');
$test->assertContains('not configured', $reloadUnavailableCommands[0] ?? '', 'Reload without reloader explains it is unavailable');

// Authorization mirrors /guard metrics and /guard players.
$trivialReloader = function (): array {
    return [
        'config' => new GuardConfig(
            adminRecipients:     ['internal_admin'],
            onConnectMessageTemplate: 'x',
            onConnectActions:    [],
            onMatchActions:      [],
            retryDelaysMs:       [1],
            maxAttempts:         1,
            cacheTtlSeconds:     1,
            dedupeWindowSeconds: 1,
        ),
        'matcher' => new Matcher([]),
    ];
};

$reloadUnauthorizedCommands = [];
$reloadUnauthorizedGuard = $buildGuardForReloadTest(['internal_admin'], $reloadUnauthorizedCommands, $trivialReloader);
$reloadUnauthorizedGuard->handleLogLine('INVALID_COMMAND guard regular_user 8.8.8.8 1 reload');
$test->assertEquals(0, count($reloadUnauthorizedCommands), 'Unauthorized reload request is ignored silently');

$reloadModeratorCommands = [];
$reloadModeratorGuard = $buildGuardForReloadTest(['internal_admin'], $reloadModeratorCommands, $trivialReloader);
$reloadModeratorGuard->handleLogLine('INVALID_COMMAND guard moderator_user 8.8.4.4 2 reload');
$test->assertEquals(1, count($reloadModeratorCommands), 'Moderator (player_level >= 2) reload request is processed');
$test->assertContains('PLAYER_MESSAGE moderator_user', $reloadModeratorCommands[0] ?? '', 'Moderator reload confirmation targets the moderator');

// SIGHUP-style broadcast reload (reloadConfigurationForAllAdmins) notifies only present admins.
$broadcastCommands = [];
$broadcastGuard = $buildGuardForReloadTest(['admin_online', 'admin_offline'], $broadcastCommands, function (): array {
    return [
        'config' => new GuardConfig(
            adminRecipients:     ['admin_online', 'admin_offline'],
            onConnectMessageTemplate: 'x',
            onConnectActions:    [],
            onMatchActions:      [],
            retryDelaysMs:       [1],
            maxAttempts:         1,
            cacheTtlSeconds:     1,
            dedupeWindowSeconds: 1,
        ),
        'matcher' => new Matcher([['name' => 'r', 'pattern' => '/x/i']]),
    ];
});
$broadcastReflection = new ReflectionClass($broadcastGuard);
$broadcastOnlineProperty = $broadcastReflection->getProperty('onlinePlayers');
$broadcastOnlineProperty->setAccessible(true);
$broadcastOnlineProperty->setValue($broadcastGuard, [
    'admin_online' => ['player_id' => 'admin_online', 'player_name' => 'admin_online', 'player_ip' => '5.5.5.5', 'player_country' => 'unknown', 'player_network' => 'unknown', 'player_timezone' => null],
]);

$broadcastGuard->reloadConfigurationForAllAdmins();

$test->assertEquals(1, count($broadcastCommands), 'Broadcast reload notifies only present admins');
$test->assertContains('PLAYER_MESSAGE admin_online', $broadcastCommands[0] ?? '', 'Broadcast reload confirmation targets the present admin');
$test->assertNotContains('admin_offline', $broadcastCommands[0] ?? '', 'Broadcast reload confirmation skips the absent admin');

echo "\n";

// ===================================================================
// Test 12: Quote-escaping regression (F1 security fix, 2026-07-08)
// ===================================================================
echo "Test 12: Quote-escaping in /guard players and /guard metrics (F1 fix)\n";
echo str_repeat("-", 60) . "\n";

// A rendered command is "well-formed" here if, after removing every escaped
// quote (\"), exactly 2 unescaped quotes remain: the template's own opening
// and closing delimiter. More than 2 means an attacker-controlled value broke
// out of the quoted argument.
$hasWellFormedQuoting = static function (string $command): bool {
    return substr_count(str_replace('\\"', '', $command), '"') === 2;
};

$quotePlayersMetrics = new Metrics();
$quotePlayersCommands = [];
$quotePlayersGuard = $buildGuardForRemoteCommandTest(['internal_admin'], $quotePlayersCommands, $quotePlayersMetrics);
$quotePlayersReflection = new ReflectionClass($quotePlayersGuard);
$quotePlayersOnlineProperty = $quotePlayersReflection->getProperty('onlinePlayers');
$quotePlayersOnlineProperty->setAccessible(true);
$quotePlayersOnlineProperty->setValue($quotePlayersGuard, [
    'p4"drop' => [
        'player_id' => 'p4"drop',
        'player_name' => 'Player "Quote" Name',
        'player_ip' => '8.8.8.8',
        'player_country' => 'Some "Place"',
        'player_network' => 'Net "Work"',
        'player_timezone' => null,
    ],
]);

$quotePlayersGuard->handleLogLine('INVALID_COMMAND guard internal_admin 8.8.8.8 2 players');

$quotePlayersRow = array_values(array_filter(
    $quotePlayersCommands,
    static fn (string $command): bool => str_contains($command, 'id=0xffff00')
));

$test->assertEquals(1, count($quotePlayersRow), '/guard players emits one row for a player with a quote in id/name');
$test->assertContains('\\"', $quotePlayersRow[0] ?? '', '/guard players escapes embedded double quotes');
$test->assertEquals(true, $hasWellFormedQuoting($quotePlayersRow[0] ?? ''), '/guard players output has no unescaped quote breakout');

$realOnMetricsTemplates = (json_decode((string) file_get_contents(__DIR__ . '/config/actions.json'), true))['onMetrics'] ?? [];

$quoteMetricsMetrics = new Metrics();
$quoteMetricsMetrics->recordLastAction('p4"drop', 'vpn"rule');
$quoteMetricsCommands = [];
$quoteMetricsRegistry = new ActionRegistry(function (string $command) use (&$quoteMetricsCommands): void {
    $quoteMetricsCommands[] = $command;
});
$quoteMetricsGuard = new Guard(
    new IpInfoClient('https://ipinfo.io', null, 2, 0, $quoteMetricsMetrics),
    new Matcher([]),
    $quoteMetricsRegistry,
    new Logger(),
    new GuardConfig(
        adminRecipients:     ['internal_admin'],
        onConnectMessageTemplate: 'x',
        onConnectActions:    [],
        onMatchActions:      [],
        retryDelaysMs:       [100],
        maxAttempts:         1,
        cacheTtlSeconds:     60,
        dedupeWindowSeconds: 15,
        onMetricsActions:    $realOnMetricsTemplates,
    ),
    $quoteMetricsMetrics
);
$quoteMetricsReflection = new ReflectionClass($quoteMetricsGuard);
$quoteMetricsOnlineProperty = $quoteMetricsReflection->getProperty('onlinePlayers');
$quoteMetricsOnlineProperty->setAccessible(true);
$quoteMetricsOnlineProperty->setValue($quoteMetricsGuard, [
    'internal_admin' => ['player_id' => 'internal_admin', 'player_name' => 'internal_admin', 'player_ip' => '1.2.3.4', 'player_country' => 'unknown', 'player_network' => 'unknown', 'player_timezone' => null],
]);

$quoteMetricsGuard->reportMetrics();

$test->assertEquals(1, count($quoteMetricsCommands), '/guard metrics emits one command to the present admin');
$test->assertContains('\\"', $quoteMetricsCommands[0] ?? '', '/guard metrics escapes embedded double quotes in last_action_who/why');
$test->assertEquals(true, $hasWellFormedQuoting($quoteMetricsCommands[0] ?? ''), '/guard metrics output has no unescaped quote breakout');

echo "\n";

// ===================================================================
// Final Report
// ===================================================================
exit($test->report());
