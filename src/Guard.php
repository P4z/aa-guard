<?php

declare(strict_types=1);

namespace AAGuard;

final class Guard
{
    private IpInfoClient $ipInfoClient;
    private Matcher $matcher;
    private ActionRegistry $actions;
    private Logger $logger;
    private GuardConfig $config;
    private Metrics $metrics;

    /** @var array<string, array{networkName:string, country:string, countryCode:string, countryName:string, expiresAt:float}> */
    private array $ipCache = [];

    /** @var array<string, array{playerId:string, ip:string, displayName:string, attempts:int, nextAttemptAt:float}> */
    private array $pendingChecks = [];

    /** @var array<string, float> */
    private array $recentActions = [];

    public function __construct(
        IpInfoClient $ipInfoClient,
        Matcher $matcher,
        ActionRegistry $actions,
        Logger $logger,
        GuardConfig $config,
        Metrics $metrics
    ) {
        $this->ipInfoClient = $ipInfoClient;
        $this->matcher = $matcher;
        $this->actions = $actions;
        $this->logger = $logger;
        $this->config = $config;
        $this->metrics = $metrics;
    }

    public function getConfig(): GuardConfig
    {
        return $this->config;
    }

    public function handleLogLine(string $line): void
    {
        $event = $this->parsePlayerEnteredGrid($line);
        if ($event === null) {
            return;
        }

        $this->evaluatePlayer($event['playerId'], $event['ip'], $event['displayName'], 0);
    }

    public function processPendingChecks(): void
    {
        $now = microtime(true);

        foreach ($this->pendingChecks as $key => $pending) {
            if ($pending['nextAttemptAt'] > $now) {
                continue;
            }

            unset($this->pendingChecks[$key]);
            $this->evaluatePlayer($pending['playerId'], $pending['ip'], $pending['displayName'], $pending['attempts']);
        }
    }

    public function housekeeping(): void
    {
        $now = microtime(true);

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

    private function evaluatePlayer(string $playerId, string $ip, string $displayName, int $attempt): void
    {
        $lookup = $this->getLookupData($ip);

        $countryName = 'unknown';
        $countryCode = 'unknown';
        $networkName = 'unknown';

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
        }

        if ($attempt === 0) {
            $this->emitConnectionNote($playerId, $countryCode, $countryName, $networkName);
        }

        if ($lookup === null) {
            $overrideDelayMs = $this->ipInfoClient->isRateLimited()
                ? $this->ipInfoClient->getRateLimitRetryAfterMs()
                : null;
            $this->scheduleRetry($playerId, $ip, $displayName, $attempt + 1, $overrideDelayMs);
            return;
        }

        $country = $countryName !== 'unknown' ? $countryName : $countryCode;
        $match = $this->matcher->match($networkName);
        if ($match['matched'] !== true || $match['ruleName'] === null) {
            $this->logger->debug(sprintf('No banned match for %s (%s) network=%s', $playerId, $ip, $networkName));
            return;
        }

        $dedupeKey = $playerId . '|' . $match['ruleName'];
        if ($this->isDuplicateAction($dedupeKey)) {
            return;
        }

        $this->recentActions[$dedupeKey] = microtime(true);
        $this->metrics->bans++;

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

    /**
     * @return array{networkName:string, country:string, countryCode:string, countryName:string}|null
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

        $this->ipCache[$ip] = [
            'networkName' => $result['networkName'],
            'country' => $country,
            'countryCode' => $countryCode,
            'countryName' => $countryName,
            'expiresAt' => $now + $this->config->cacheTtlSeconds,
        ];

        return [
            'networkName' => $result['networkName'],
            'country' => $country,
            'countryCode' => $countryCode,
            'countryName' => $countryName,
        ];
    }

    private function emitConnectionNote(string $playerId, string $countryCode, string $countryName, string $networkName): void
    {
        $country = $countryName !== 'unknown' ? $countryName : $countryCode;

        $baseContext = [
            'player_id'    => $playerId,
            'country'      => $country,
            'country_code' => $countryCode,
            'country_name' => $countryName,
            'network_name' => $networkName,
        ];
        $baseContext['msg'] = $this->renderOnConnectMessage($baseContext);
        $emittedAdminMessage = false;

        foreach ($this->config->onConnectActions as $template) {
            if (str_contains($template, '{{admin}}')) {
                $emittedAdminMessage = true;
                foreach ($this->config->adminRecipients as $admin) {
                    $context = array_merge($baseContext, ['admin' => $admin]);
                    $this->actions->executeTemplatesWithRawValues([$template], $context, ['msg']);
                }
                continue;
            }

            $this->actions->executeTemplatesWithRawValues([$template], $baseContext, ['msg']);
        }

        // Guarantee at least one admin-targeted join message per admin on every join.
        if (!$emittedAdminMessage && !empty($this->config->adminRecipients)) {
            foreach ($this->config->adminRecipients as $admin) {
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
        string $playerId,
        string $ip,
        string $displayName,
        int $attempt,
        ?int $delayMsOverride = null
    ): void {
        if ($attempt > $this->config->maxAttempts) {
            $this->logger->warning(sprintf('Giving up IP lookup for %s (%s) after %d attempts', $playerId, $ip, $attempt - 1));
            return;
        }

        $delayMs = $delayMsOverride
            ?? ($this->config->retryDelaysMs[$attempt - 1]
                ?? $this->config->retryDelaysMs[count($this->config->retryDelaysMs) - 1]
                ?? 1000);
        $nextAttemptAt = microtime(true) + ($delayMs / 1000);

        $key = $playerId . '|' . $ip;

        // Don't overwrite a pending retry that is already at a higher attempt count.
        // This prevents a fast reconnect from resetting the retry counter, which
        // could allow infinite retries if the player keeps reconnecting.
        if (isset($this->pendingChecks[$key]) && $this->pendingChecks[$key]['attempts'] >= $attempt) {
            return;
        }

        $this->pendingChecks[$key] = [
            'playerId' => $playerId,
            'ip' => $ip,
            'displayName' => $displayName,
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
        $this->logger->debug($this->metrics->toLogString());

        if (empty($this->config->adminRecipients) || empty($this->config->onMetricsActions)) {
            return;
        }

        $context = $this->metrics->toTemplateContext();
        foreach ($this->config->adminRecipients as $admin) {
            $this->actions->executeTemplates(
                $this->config->onMetricsActions,
                array_merge($context, ['admin' => $admin])
            );
        }
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
