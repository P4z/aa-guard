<?php

declare(strict_types=1);

namespace AAGuard;

final class Guard
{
    private const HOUSEKEEPING_INTERVAL_SECONDS = 1.0;
    private const MIN_REMOTE_COMMAND_LEVEL = 2;

    private IpInfoClient $ipInfoClient;
    private Matcher $matcher;
    private ActionRegistry $actions;
    private Logger $logger;
    private GuardConfig $config;
    private Metrics $metrics;
    private ?\Closure $configReloader;

    /** @var array<string, array{networkName:string, country:string, countryCode:string, countryName:string, timezone:?string, expiresAt:float}> */
    private array $ipCache = [];

    /** @var array<string, array{ip:string, attempts:int, nextAttemptAt:float}> */
    private array $pendingChecks = [];

    /** @var array<string, float> */
    private array $recentActions = [];

    /** @var array<string, array{player_id:string, player_name:string, player_ip:string, player_country:string, player_network:string, player_timezone:?string}> */
    private array $onlinePlayers = [];

    private int $nextPlayerSessionId = 1;
    private float $nextHousekeepingAt = 0.0;

    /**
     * @param (\Closure():array{config:GuardConfig, matcher:Matcher})|null $configReloader
     *   Re-reads configuration from disk and returns a fresh GuardConfig/Matcher pair.
     *   Must throw on invalid/missing configuration; must not exit the process.
     *   Pass null to disable `/guard reload` (it will reply with a failure message).
     */
    public function __construct(
        IpInfoClient $ipInfoClient,
        Matcher $matcher,
        ActionRegistry $actions,
        Logger $logger,
        GuardConfig $config,
        Metrics $metrics,
        ?\Closure $configReloader = null
    ) {
        $this->ipInfoClient = $ipInfoClient;
        $this->matcher = $matcher;
        $this->actions = $actions;
        $this->logger = $logger;
        $this->config = $config;
        $this->metrics = $metrics;
        $this->configReloader = $configReloader;
    }

    public function getConfig(): GuardConfig
    {
        return $this->config;
    }

    /**
     * Admin recipients (from the current, reload-aware config) who are
     * currently tracked as online. Used by callers outside this class (e.g.
     * the debug-log forwarder in bin/aa_guard.php) that need the same
     * presence filtering already applied to onConnect/onMetrics/reload output.
     *
     * @return array<int, string>
     */
    public function getPresentAdminRecipients(): array
    {
        return $this->filterPresentAdminRecipients($this->config->adminRecipients, []);
    }

    public function handleLogLine(string $line): void
    {
        $event = $this->parsePlayerEnteredGrid($line);
        if ($event !== null) {
            $this->startPlayerEvaluation($event['playerId'], $event['ip'], $event['displayName']);
            return;
        }

        $spectatorEvent = $this->parsePlayerEnteredSpectator($line);
        if ($spectatorEvent !== null) {
            $this->startPlayerEvaluation($spectatorEvent['playerId'], $spectatorEvent['ip'], $spectatorEvent['displayName']);
            return;
        }

        $renamedEvent = $this->parsePlayerRenamed($line);
        if ($renamedEvent !== null) {
            $this->handlePlayerRenamed(
                $renamedEvent['oldPlayerId'],
                $renamedEvent['newPlayerId'],
                $renamedEvent['ip'],
                $renamedEvent['displayName']
            );
            return;
        }

        $leftEvent = $this->parsePlayerLeft($line);
        if ($leftEvent !== null) {
            $this->handlePlayerLeft($leftEvent['playerId'], $leftEvent['ip']);
            return;
        }

        $remoteCommand = $this->parseInvalidCommand($line);
        if ($remoteCommand !== null) {
            $this->handleRemoteCommand($remoteCommand);
        }
    }

    public function processPendingChecks(): void
    {
        $now = microtime(true);

        foreach ($this->pendingChecks as $playerKey => $pending) {
            if ($pending['nextAttemptAt'] > $now) {
                continue;
            }

            unset($this->pendingChecks[$playerKey]);

            if ($this->getActivePlayer((string) $playerKey, $pending['ip']) === null) {
                $this->logger->debug(sprintf('Cancelled stale IP lookup for %s', $pending['ip']));
                continue;
            }

            $this->evaluatePlayer((string) $playerKey, $pending['attempts'], $pending['ip']);
        }
    }

    public function housekeeping(): void
    {
        $now = microtime(true);
        if ($this->nextHousekeepingAt > $now) {
            return;
        }

        $this->nextHousekeepingAt = $now + self::HOUSEKEEPING_INTERVAL_SECONDS;

        foreach ($this->ipCache as $ip => $cached) {
            if ($cached['expiresAt'] <= $now) {
                unset($this->ipCache[$ip]);
            }
        }

        foreach ($this->recentActions as $key => $timestamp) {
            if (($now - $timestamp) > $this->config->dedupeWindowSeconds) {
                unset($this->recentActions[$key]);
            }
        }
    }

    /**
     * @return array{playerId:string, ip:string, displayName:string}|null
     */
    private function parsePlayerEnteredGrid(string $line): ?array
    {
        $trimmed = trim($line);
        if ($trimmed === '') {
            return null;
        }

        $matches = [];
        $ok = preg_match('/^PLAYER_ENTERED_GRID\s+(\S+)\s+(\S+)\s+(.+)$/', $trimmed, $matches);
        if ($ok !== 1) {
            return null;
        }

        $ip = $matches[2];
        
        // Validate IP address properly to prevent invalid IPs like 999.999.999.999
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
            $this->logger->warning(sprintf('Invalid IP address: %s', $ip));
            $this->metrics->invalidIps++;
            return null;
        }

        return [
            'playerId' => $matches[1],
            'ip' => $ip,
            'displayName' => $matches[3],
        ];
    }

    /**
     * @return array{playerId:string, ip:string, displayName:string}|null
     */
    private function parsePlayerEnteredSpectator(string $line): ?array
    {
        $trimmed = trim($line);
        if ($trimmed === '') {
            return null;
        }

        $matches = [];
        $ok = preg_match('/^PLAYER_ENTERED_SPECTATOR\s+(\S+)\s+(\S+)\s+(.+)$/', $trimmed, $matches);
        if ($ok !== 1) {
            return null;
        }

        $ip = $matches[2];
        
        // Validate IP address properly to prevent invalid IPs like 999.999.999.999
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
            $this->logger->warning(sprintf('Invalid IP address: %s', $ip));
            $this->metrics->invalidIps++;
            return null;
        }

        return [
            'playerId' => $matches[1],
            'ip' => $ip,
            'displayName' => $matches[3],
        ];
    }

    /**
     * @return array{playerId:string, ip:string, displayName:string}|null
     */
    private function parsePlayerLeft(string $line): ?array
    {
        $trimmed = trim($line);
        if ($trimmed === '') {
            return null;
        }

        $matches = [];
        $ok = preg_match('/^PLAYER_LEFT\s+(\S+)\s+(\S+)\s+(.+)$/', $trimmed, $matches);
        if ($ok !== 1) {
            return null;
        }

        return [
            'playerId' => $matches[1],
            'ip' => $matches[2],
            'displayName' => $matches[3],
        ];
    }

    /**
     * @return array{oldPlayerId:string, newPlayerId:string, ip:string, didLogin:bool, displayName:string}|null
     */
    private function parsePlayerRenamed(string $line): ?array
    {
        $trimmed = trim($line);
        if ($trimmed === '') {
            return null;
        }

        $matches = [];
        $ok = preg_match('/^PLAYER_RENAMED\s+(\S+)\s+(\S+)\s+(\S+)\s+([01])\s+(.+)$/', $trimmed, $matches);
        if ($ok !== 1) {
            return null;
        }

        return [
            'oldPlayerId' => $matches[1],
            'newPlayerId' => $matches[2],
            'ip' => $matches[3],
            'didLogin' => $matches[4] === '1',
            'displayName' => $matches[5],
        ];
    }

    /**
     * @return array{commandName:string, playerId:string, playerIp:string, playerLevel:int, commandArgs:string}|null
     */
    private function parseInvalidCommand(string $line): ?array
    {
        $trimmed = trim($line);
        if ($trimmed === '') {
            return null;
        }

        $parts = preg_split('/\s+/', $trimmed);
        if (!is_array($parts) || count($parts) < 5 || strtoupper($parts[0]) !== 'INVALID_COMMAND') {
            return null;
        }

        // Support both observed ladderlog layouts:
        // 1) INVALID_COMMAND <command> <player_id> <player_ip> <player_level> [args...]
        // 2) INVALID_COMMAND <player_id> <player_ip> <player_level> <command> [args...]
        $parsed = $this->tryParseInvalidCommandLayout(
            commandName: $parts[1],
            playerId: $parts[2],
            playerIp: $parts[3],
            playerLevel: $parts[4],
            commandArgs: array_slice($parts, 5)
        );

        if ($parsed !== null) {
            return $parsed;
        }

        return $this->tryParseInvalidCommandLayout(
            commandName: $parts[4],
            playerId: $parts[1],
            playerIp: $parts[2],
            playerLevel: $parts[3],
            commandArgs: array_slice($parts, 5)
        );
    }

    /**
     * @param array<int, string> $commandArgs
     * @return array{commandName:string, playerId:string, playerIp:string, playerLevel:int, commandArgs:string}|null
     */
    private function tryParseInvalidCommandLayout(
        string $commandName,
        string $playerId,
        string $playerIp,
        string $playerLevel,
        array $commandArgs
    ): ?array {
        $normalizedCommandName = $this->normalizeRemoteCommandName($commandName);
        if ($normalizedCommandName === '') {
            return null;
        }

        if (filter_var($playerIp, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
            return null;
        }

        $playerLevelInt = filter_var($playerLevel, FILTER_VALIDATE_INT);
        if ($playerLevelInt === false) {
            return null;
        }

        return [
            'commandName' => $normalizedCommandName,
            'playerId' => $playerId,
            'playerIp' => $playerIp,
            'playerLevel' => $playerLevelInt,
            'commandArgs' => trim(implode(' ', $commandArgs)),
        ];
    }

    private function normalizeRemoteCommandName(string $commandName): string
    {
        $normalized = strtolower(trim($commandName));
        $normalized = trim($normalized, "\"'");

        return ltrim($normalized, '/');
    }

    /**
     * @param array{commandName:string, playerId:string, playerIp:string, playerLevel:int, commandArgs:string} $event
     */
    private function handleRemoteCommand(array $event): void
    {
        switch (strtolower($event['commandName'])) {
            case 'guard':
                $this->handleGuardRemoteCommand($event);
                break;
        }
    }

    /**
     * @param array{commandName:string, playerId:string, playerIp:string, playerLevel:int, commandArgs:string} $event
     */
    private function handleGuardRemoteCommand(array $event): void
    {
        $subcommand = $this->parseRemoteSubcommand($event['commandArgs']);
        if ($subcommand === null) {
            $this->replyWithRandomErrorQuote($event['playerId']);
            return;
        }

        switch ($subcommand['name']) {
            case 'metrics':
                if (!$this->isRemoteCommandAuthorized($event['playerId'], $event['playerLevel'])) {
                    $this->replyWithRandomErrorQuote($event['playerId']);
                    return;
                }

                $this->reportMetricsForRecipient($event['playerId']);
                break;
            case 'players':
                if (!$this->isRemoteCommandAuthorized($event['playerId'], $event['playerLevel'])) {
                    $this->replyWithRandomErrorQuote($event['playerId']);
                    return;
                }

                $this->reportPlayersForRecipient($event['playerId']);
                break;
            case 'reload':
                if (!$this->isRemoteCommandAuthorized($event['playerId'], $event['playerLevel'])) {
                    $this->replyWithRandomErrorQuote($event['playerId']);
                    return;
                }

                $this->handleReloadCommand($event['playerId']);
                break;
            default:
                $this->replyWithRandomErrorQuote($event['playerId']);
                break;
        }
    }

    /**
     * Replies in private to an unhandled/unauthorized `/guard` invocation
     * (no subcommand, unknown subcommand, or not authorized) with a random
     * flavor quote from config (`onErrorMessage`), delivered via the
     * configurable `onError` action templates. No-op if either is empty.
     */
    private function replyWithRandomErrorQuote(string $playerId): void
    {
        if (empty($this->config->onErrorQuotes) || empty($this->config->onErrorActions)) {
            return;
        }

        $quote = $this->config->onErrorQuotes[array_rand($this->config->onErrorQuotes)];

        $this->actions->executeTemplatesWithRawValues(
            $this->config->onErrorActions,
            ['player_id' => $playerId, 'msg' => $quote],
            ['msg']
        );
    }

    /**
     * @return array{name:string, arguments:string}|null
     */
    private function parseRemoteSubcommand(string $commandArgs): ?array
    {
        $trimmed = trim($commandArgs);
        if ($trimmed === '') {
            return null;
        }

        $parts = preg_split('/\s+/', $trimmed, 2);
        if (!is_array($parts)) {
            return null;
        }

        return [
            'name' => strtolower($parts[0]),
            'arguments' => $parts[1] ?? '',
        ];
    }

    private function isRemoteCommandAuthorized(string $playerId, int $playerLevel): bool
    {
        if ($playerLevel >= self::MIN_REMOTE_COMMAND_LEVEL) {
            return true;
        }

        $normalizedPlayerId = strtolower($playerId);
        foreach ($this->config->adminRecipients as $adminRecipient) {
            if (strtolower($adminRecipient) === $normalizedPlayerId) {
                return true;
            }
        }

        return false;
    }

    private function startPlayerEvaluation(string $playerId, string $ip, string $displayName): void
    {
        $playerKey = $this->recordOnlinePlayer($playerId, $displayName, $ip);
        $this->evaluatePlayer($playerKey, 0, $ip);
    }

    private function evaluatePlayer(string $playerKey, int $attempt, string $expectedIp): void
    {
        $player = $this->getActivePlayer($playerKey, $expectedIp);
        if ($player === null) {
            $this->logger->debug(sprintf('Cancelled stale IP lookup for %s', $expectedIp));
            return;
        }

        $playerId = $player['player_id'];
        $ip = $player['player_ip'];
        $lookup = $this->getLookupData($ip);

        $countryName = 'unknown';
        $countryCode = 'unknown';
        $networkName = 'unknown';
        $timezone = null;

        if ($lookup !== null) {
            if (isset($lookup['countryName']) && is_string($lookup['countryName']) && trim($lookup['countryName']) !== '') {
                $countryName = trim($lookup['countryName']);
            }

            if (isset($lookup['countryCode']) && is_string($lookup['countryCode']) && trim($lookup['countryCode']) !== '') {
                $countryCode = trim($lookup['countryCode']);
            }

            if (isset($lookup['networkName']) && is_string($lookup['networkName']) && trim($lookup['networkName']) !== '') {
                $networkName = trim($lookup['networkName']);
            }

            if (isset($lookup['timezone']) && is_string($lookup['timezone']) && trim($lookup['timezone']) !== '') {
                $timezone = trim($lookup['timezone']);
            }
        }

        $country = $countryName !== 'unknown' ? $countryName : $countryCode;

        // A delayed lookup belongs to one tracked connection, not to a nickname.
        // Rename keeps the same storage key; leave/reconnect removes or replaces it.
        $player = $this->getActivePlayer($playerKey, $ip);
        if ($player === null) {
            $this->logger->debug(sprintf('Cancelled stale IP lookup for %s', $ip));
            return;
        }

        $this->onlinePlayers[$playerKey]['player_country'] = $country;
        $this->onlinePlayers[$playerKey]['player_network'] = $networkName;
        $this->onlinePlayers[$playerKey]['player_timezone'] = $timezone;

        $playerId = $player['player_id'];

        if ($attempt === 0) {
            $this->emitConnectionNote($playerId, $countryCode, $countryName, $networkName, $timezone);
        }

        if ($lookup === null) {
            $overrideDelayMs = $this->ipInfoClient->isRateLimited()
                ? $this->ipInfoClient->getRateLimitRetryAfterMs()
                : null;
            $this->scheduleRetry($playerKey, $ip, $attempt + 1, $overrideDelayMs);
            return;
        }

        $match = $this->matcher->match($networkName);
        if ($match['matched'] !== true || $match['ruleName'] === null) {
            $this->logger->debug(sprintf('No banned match for %s (%s) network=%s', $playerId, $ip, $networkName));
            return;
        }

        // Resolve current values immediately before action. Rename may change
        // player_id/display_name, but IP and stable session key must still match.
        $player = $this->getActivePlayer($playerKey, $ip);
        if ($player === null) {
            $this->logger->debug(sprintf('Cancelled stale matched action for %s', $ip));
            return;
        }

        $playerId = $player['player_id'];
        $displayName = $player['player_name'];

        $dedupeKey = $playerId . '|' . $match['ruleName'];
        if ($this->isDuplicateAction($dedupeKey)) {
            return;
        }

        $this->recentActions[$dedupeKey] = microtime(true);
        $this->metrics->bans++;
        $this->metrics->recordLastAction($playerId, $match['ruleName']);

        $this->actions->executeTemplates($this->config->onMatchActions, [
            'player_id' => $playerId,
            'display_name' => $displayName,
            'ip' => $ip,
            'country' => $country,
            'network_name' => $networkName,
            'rule_name' => $match['ruleName'],
        ]);

        $this->logger->warning(sprintf(
            'Executed actions for %s (%s), network=%s, rule=%s',
            $playerId,
            $ip,
            $networkName,
            $match['ruleName']
        ));
    }

    private function recordOnlinePlayer(
        string $playerId,
        string $playerName,
        string $ip
    ): string {
        // A fresh enter event supersedes any stale tracked connection using the
        // same player_id. Its old pending lookup must never target the new one.
        foreach ($this->onlinePlayers as $existingKey => $existingPlayer) {
            if ($existingPlayer['player_id'] === $playerId) {
                unset($this->onlinePlayers[$existingKey], $this->pendingChecks[$existingKey]);
            }
        }

        $playerKey = sprintf('p:%s:%d', $playerId, $this->nextPlayerSessionId++);
        $this->onlinePlayers[$playerKey] = [
            'player_id' => $playerId,
            'player_name' => $playerName,
            'player_ip' => $ip,
            'player_country' => 'unknown',
            'player_network' => 'unknown',
            'player_timezone' => null,
        ];

        return $playerKey;
    }

    private function handlePlayerLeft(string $playerId, string $ip): void
    {
        foreach ($this->onlinePlayers as $playerKey => $player) {
            if ($player['player_id'] === $playerId && $player['player_ip'] === $ip) {
                unset($this->onlinePlayers[$playerKey], $this->pendingChecks[$playerKey]);
            }
        }

        $this->logger->debug(sprintf('Player left: %s (%s), removed from tracked online players', $playerId, $ip));
    }

    private function handlePlayerRenamed(string $oldPlayerId, string $newPlayerId, string $ip, string $displayName): void
    {
        foreach ($this->onlinePlayers as $playerKey => $player) {
            if ($player['player_id'] !== $oldPlayerId) {
                continue;
            }

            if ($player['player_ip'] !== $ip) {
                unset($this->onlinePlayers[$playerKey], $this->pendingChecks[$playerKey]);
                $this->logger->warning(sprintf(
                    'Cancelled tracked session after rename IP mismatch: %s -> %s (expected %s, got %s)',
                    $oldPlayerId,
                    $newPlayerId,
                    $player['player_ip'],
                    $ip
                ));
                return;
            }

            $this->onlinePlayers[$playerKey]['player_id'] = $newPlayerId;
            $this->onlinePlayers[$playerKey]['player_name'] = $displayName;
            $this->logger->debug(sprintf(
                'Player renamed: %s -> %s (%s), updated tracked session',
                $oldPlayerId,
                $newPlayerId,
                $ip
            ));
            return;
        }

        // Some login transitions repeat the already-current player_id.
        foreach ($this->onlinePlayers as $playerKey => $player) {
            if ($player['player_id'] === $newPlayerId && $player['player_ip'] === $ip) {
                $this->onlinePlayers[$playerKey]['player_name'] = $displayName;
                return;
            }
        }
    }

    /**
     * @return array{player_id:string, player_name:string, player_ip:string, player_country:string, player_network:string, player_timezone:?string}|null
     */
    private function getActivePlayer(string $playerKey, string $expectedIp): ?array
    {
        $player = $this->onlinePlayers[$playerKey] ?? null;
        if ($player === null || $player['player_ip'] !== $expectedIp) {
            return null;
        }

        return $player;
    }

    /**
     * @return array{networkName:string, country:string, countryCode:string, countryName:string, timezone:?string}|null
     */
    private function getLookupData(string $ip): ?array
    {
        $now = microtime(true);

        if (isset($this->ipCache[$ip]) && $this->ipCache[$ip]['expiresAt'] > $now) {
            $this->metrics->cacheHits++;
            return [
                'networkName' => $this->ipCache[$ip]['networkName'],
                'country' => $this->ipCache[$ip]['country'],
                'countryCode' => $this->ipCache[$ip]['countryCode'],
                'countryName' => $this->ipCache[$ip]['countryName'],
                'timezone' => $this->ipCache[$ip]['timezone'] ?? null,
            ];
        }

        $result = $this->ipInfoClient->fetchNetworkName($ip);
        if ($result['success'] !== true || $result['networkName'] === null) {
            $error = $result['error'] ?? 'unknown_error';
            $this->logger->warning(sprintf('IP lookup failed for %s: %s', $ip, $error));
            return null;
        }

        $country = isset($result['country']) && is_string($result['country']) && trim($result['country']) !== ''
            ? trim($result['country'])
            : 'unknown';
        $countryCode = isset($result['countryCode']) && is_string($result['countryCode']) && trim($result['countryCode']) !== ''
            ? trim($result['countryCode'])
            : 'unknown';
        $countryName = isset($result['countryName']) && is_string($result['countryName']) && trim($result['countryName']) !== ''
            ? trim($result['countryName'])
            : 'unknown';
        $timezone = isset($result['timezone']) && is_string($result['timezone']) && trim($result['timezone']) !== ''
            ? trim($result['timezone'])
            : null;

        $this->ipCache[$ip] = [
            'networkName' => $result['networkName'],
            'country' => $country,
            'countryCode' => $countryCode,
            'countryName' => $countryName,
            'timezone' => $timezone,
            'expiresAt' => $now + $this->config->cacheTtlSeconds,
        ];

        return [
            'networkName' => $result['networkName'],
            'country' => $country,
            'countryCode' => $countryCode,
            'countryName' => $countryName,
            'timezone' => $timezone,
        ];
    }

    private function emitConnectionNote(string $playerId, string $countryCode, string $countryName, string $networkName, ?string $timezone = null): void
    {
        $country = $countryName !== 'unknown' ? $countryName : $countryCode;

        $baseContext = [
            'player_id'    => $playerId,
            'country'      => $country,
            'country_code' => $countryCode,
            'country_name' => $countryName,
            'network_name' => $networkName,
            'time'         => $this->localTimeForTimezone($timezone),
        ];
        $baseContext['msg'] = $this->renderOnConnectMessage($baseContext);
        $emittedAdminMessage = false;
        $presentAdmins = $this->filterPresentAdminRecipients($this->config->adminRecipients, []);

        foreach ($this->config->onConnectActions as $template) {
            if (str_contains($template, '{{admin}}')) {
                $emittedAdminMessage = true;
                foreach ($presentAdmins as $admin) {
                    $context = array_merge($baseContext, ['admin' => $admin]);
                    $this->actions->executeTemplatesWithRawValues([$template], $context, ['msg']);
                }
                continue;
            }

            $this->actions->executeTemplatesWithRawValues([$template], $baseContext, ['msg']);
        }

        // Guarantee at least one admin-targeted join message per present admin on every join.
        if (!$emittedAdminMessage && !empty($presentAdmins)) {
            foreach ($presentAdmins as $admin) {
                $context = array_merge($baseContext, ['admin' => $admin]);
                $this->actions->executeTemplatesWithRawValues(['PLAYER_MESSAGE {{admin}} "{{msg}}"'], $context, ['msg']);
            }
        }
    }

    /**
     * @param array<string, string> $context
     */
    private function renderOnConnectMessage(array $context): string
    {
        $map = [];
        foreach ($context as $key => $value) {
            $map['{{' . $key . '}}'] = $value;
        }

        return trim(strtr($this->config->onConnectMessageTemplate, $map));
    }

    private function scheduleRetry(
        string $playerKey,
        string $ip,
        int $attempt,
        ?int $delayMsOverride = null
    ): void {
        $player = $this->getActivePlayer($playerKey, $ip);
        if ($player === null) {
            return;
        }

        $playerId = $player['player_id'];
        if ($attempt > $this->config->maxAttempts) {
            $this->logger->warning(sprintf('Giving up IP lookup for %s (%s) after %d attempts', $playerId, $ip, $attempt - 1));
            return;
        }

        $delayMs = $delayMsOverride
            ?? ($this->config->retryDelaysMs[$attempt - 1]
                ?? $this->config->retryDelaysMs[count($this->config->retryDelaysMs) - 1]
                ?? 1000);
        $nextAttemptAt = microtime(true) + ($delayMs / 1000);

        // Don't overwrite a pending retry that is already at a higher attempt count.
        // This prevents a fast reconnect from resetting the retry counter, which
        // could allow infinite retries if the player keeps reconnecting.
        if (isset($this->pendingChecks[$playerKey]) && $this->pendingChecks[$playerKey]['attempts'] >= $attempt) {
            return;
        }

        $this->pendingChecks[$playerKey] = [
            'ip' => $ip,
            'attempts' => $attempt,
            'nextAttemptAt' => $nextAttemptAt,
        ];

        $this->logger->debug(sprintf(
            'Scheduled retry %d/%d for %s (%s) in %dms',
            $attempt,
            $this->config->maxAttempts,
            $playerId,
            $ip,
            $delayMs
        ));
    }

    public function reportMetrics(): void
    {
        $this->logger->debug($this->buildMetricsLogString());
        $this->emitMetricsToRecipients($this->config->adminRecipients);
    }

    /**
     * Re-reads configuration from disk via the injected reloader closure and
     * swaps it into this instance. On failure (missing reloader, invalid
     * config, thrown exception) the current config/matcher are left
     * untouched so the guard keeps running with the last-known-good state.
     *
     * NOTE: `ipInfoTimeoutSeconds` and `ipInfoRateLimitPerMinute` are consumed
     * once by IpInfoClient's constructor and are NOT reloaded here; changing
     * them requires a process restart.
     *
     * @return array{success:bool, error:?string, ruleCount:?int}
     */
    public function reloadConfiguration(): array
    {
        if ($this->configReloader === null) {
            return ['success' => false, 'error' => 'Config reload is not configured.', 'ruleCount' => null];
        }

        try {
            $reloaded = ($this->configReloader)();
        } catch (\Throwable $e) {
            $this->logger->error(sprintf('Config reload failed: %s', $e->getMessage()));
            return ['success' => false, 'error' => $e->getMessage(), 'ruleCount' => null];
        }

        $this->config = $reloaded['config'];
        $this->matcher = $reloaded['matcher'];

        $ruleCount = $this->matcher->getRuleCount();
        $this->logger->debug(sprintf('Configuration reloaded (%d rules)', $ruleCount));

        return ['success' => true, 'error' => null, 'ruleCount' => $ruleCount];
    }

    /**
     * Reloads configuration and notifies every currently present admin
     * (used by the SIGHUP handler, which has no single requesting player).
     */
    public function reloadConfigurationForAllAdmins(): void
    {
        $result = $this->reloadConfiguration();
        $presentAdmins = $this->filterPresentAdminRecipients($this->config->adminRecipients, []);
        $this->notifyReloadResult($result, $presentAdmins);
    }

    private function handleReloadCommand(string $admin): void
    {
        $result = $this->reloadConfiguration();
        $this->notifyReloadResult($result, [$admin]);
    }

    /**
     * @param array{success:bool, error:?string, ruleCount:?int} $result
     * @param array<int, string> $admins
     */
    private function notifyReloadResult(array $result, array $admins): void
    {
        foreach ($admins as $admin) {
            if ($result['success']) {
                $this->actions->executeTemplatesWithRawValues([
                    'PLAYER_MESSAGE {{admin}} "0x00ff00>> 0x888888[GUARD] 0xffffffConfiguration reloaded (0xffff00{{rule_count}}0xffffff rules)."',
                ], [
                    'admin' => $admin,
                    'rule_count' => (string) ($result['ruleCount'] ?? 0),
                ], []);
                continue;
            }

            $this->actions->executeTemplatesWithRawValues([
                'PLAYER_MESSAGE {{admin}} "0xff0000>> 0x888888[GUARD] 0xffffffConfig reload failed: 0xffff00{{error}}"',
            ], [
                'admin' => $admin,
                'error' => $result['error'] ?? 'unknown error',
            ], ['error']);
        }
    }

    private function reportMetricsForRecipient(string $admin): void
    {
        $this->logger->debug($this->buildMetricsLogString());
        $this->emitMetricsToRecipients([$admin], [$admin]);
    }

    private function reportPlayersForRecipient(string $admin): void
    {
        if (empty($this->onlinePlayers)) {
            $this->actions->executeTemplatesWithRawValues([
                'PLAYER_MESSAGE {{admin}} "0x00ff00>> 0x888888[GUARD] 0xffffffNo tracked players online."',
            ], ['admin' => $admin], []);
            return;
        }

        $players = $this->onlinePlayers;
        uasort($players, static fn (array $a, array $b): int => strcmp($a['player_id'], $b['player_id']));

        foreach ($players as $player) {
            // player_id/player_name/player_country/player_network are attacker/third-party
            // controlled and sit inside the quoted message below, so they must go through
            // the quote-escaping (raw) path, not the plain sanitizer (which never escapes `"`).
            $this->actions->executeTemplatesWithRawValues([
                'PLAYER_MESSAGE {{admin}} "0x00ff00>> 0x888888[GUARD] 0xffffffid=0xffff00{{player_id}} 0xffffffname=0xffff00{{player_name}} 0xffffffcountry=0xffff00{{player_country}} 0xffffffnetwork=0xffff00{{player_network}} 0xfffffftime=0xffff00{{time}}"',
            ], [
                'admin' => $admin,
                'player_id' => $player['player_id'],
                'player_name' => $player['player_name'],
                'player_country' => $player['player_country'],
                'player_network' => $player['player_network'],
                'time' => $this->localTimeForTimezone($player['player_timezone'] ?? null),
            ], ['player_id', 'player_name', 'player_country', 'player_network']);
        }
    }

    private function localTimeForTimezone(?string $timezone): string
    {
        if ($timezone !== null && $timezone !== '') {
            try {
                return (new \DateTimeImmutable('now', new \DateTimeZone($timezone)))->format('H:i');
            } catch (\Exception $e) {
                // Invalid/unknown IANA timezone name from provider.
            }
        }

        return 'unknown';
    }

    /**
     * @param array<int, string> $adminRecipients
     * @param array<int, string> $knownPresentRecipients
     */
    private function emitMetricsToRecipients(array $adminRecipients, array $knownPresentRecipients = []): void
    {
        if (empty($adminRecipients) || empty($this->config->onMetricsActions)) {
            return;
        }

        $presentAdminRecipients = $this->filterPresentAdminRecipients($adminRecipients, $knownPresentRecipients);
        if (empty($presentAdminRecipients)) {
            return;
        }

        $context = $this->buildMetricsContext();
        foreach ($presentAdminRecipients as $admin) {
            // last_action_who/last_action_why are attacker-controlled (a past offender's own
            // player_id / matched rule name) and the shipped onMetrics template embeds them
            // inside a quoted string, so they must use the quote-escaping (raw) path.
            $this->actions->executeTemplatesWithRawValues(
                $this->config->onMetricsActions,
                array_merge($context, ['admin' => $admin]),
                ['last_action_who', 'last_action_why']
            );
        }
    }

    /**
     * @param array<int, string> $adminRecipients
     * @param array<int, string> $knownPresentRecipients
     * @return array<int, string>
     */
    private function filterPresentAdminRecipients(array $adminRecipients, array $knownPresentRecipients): array
    {
        $presentAdminIds = [];
        foreach ($this->onlinePlayers as $player) {
            $playerId = $player['player_id'];
            $normalized = strtolower(trim((string) $playerId));
            if ($normalized !== '') {
                $presentAdminIds[$normalized] = true;
            }
        }

        foreach ($knownPresentRecipients as $recipient) {
            $normalized = strtolower(trim($recipient));
            if ($normalized !== '') {
                $presentAdminIds[$normalized] = true;
            }
        }

        $presentRecipients = [];
        foreach ($adminRecipients as $admin) {
            $normalized = strtolower(trim($admin));
            if ($normalized === '' || !isset($presentAdminIds[$normalized])) {
                continue;
            }

            $presentRecipients[] = $admin;
        }

        return $presentRecipients;
    }

    /** @return array<string, string> */
    private function buildMetricsContext(): array
    {
        return array_merge($this->metrics->toTemplateContext(), [
            'cache_size' => (string) count($this->ipCache),
        ]);
    }

    private function buildMetricsLogString(): string
    {
        return sprintf('%s cache_size=%d', $this->metrics->toLogString(), count($this->ipCache));
    }

    private function isDuplicateAction(string $dedupeKey): bool
    {
        if (!isset($this->recentActions[$dedupeKey])) {
            return false;
        }

        $lastTimestamp = $this->recentActions[$dedupeKey];
        return (microtime(true) - $lastTimestamp) <= $this->config->dedupeWindowSeconds;
    }
}
