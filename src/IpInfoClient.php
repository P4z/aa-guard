<?php

declare(strict_types=1);

namespace AAGuard;

final class IpInfoClient
{
    private const USER_AGENT = 'aa-guard/1.0';
    private string $baseUrl;
    private ?string $token;
    private int $timeoutSeconds;
    private int $rateLimit;
    private ?Metrics $metrics;
    /** @var array<string, string> */
    private array $countryCodeToName;

    /** @var list<float> */
    private array $apiCallTimestamps = [];

    public function __construct(
        string $baseUrl = 'https://ipinfo.io',
        ?string $token = null,
        int $timeoutSeconds = 2,
        int $rateLimit = 30,
        ?Metrics $metrics = null
    ) {
        $this->baseUrl = rtrim($baseUrl, '/');
        $this->token = $token;
        $this->timeoutSeconds = $timeoutSeconds;
        $this->rateLimit = $rateLimit;
        $this->metrics = $metrics;
        $this->countryCodeToName = $this->loadCountries(__DIR__ . '/../data/countries.json');
    }

    /**
     * @return array{success:bool, networkName:?string, country:?string, countryCode:?string, countryName:?string, error:?string}
     */
    public function fetchNetworkName(string $ip): array
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
            return [
                'success' => false,
                'networkName' => null,
                'country' => null,
                'countryCode' => null,
                'countryName' => null,
                'error' => 'invalid_ip',
            ];
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
            return [
                'success' => false,
                'networkName' => null,
                'country' => null,
                'countryCode' => null,
                'countryName' => null,
                'error' => 'private_ip',
            ];
        }

        $url = sprintf('%s/%s/json', $this->baseUrl, rawurlencode($ip));

        $now = microtime(true);
        $this->pruneApiCallTimestamps($now);
        if (count($this->apiCallTimestamps) >= $this->rateLimit) {
            if ($this->metrics !== null) {
                $this->metrics->rateLimited++;
            }
            return [
                'success'     => false,
                'networkName' => null,
                'country'     => null,
                'countryCode' => null,
                'countryName' => null,
                'error'       => 'rate_limited',
            ];
        }
        $this->apiCallTimestamps[] = $now;
        if ($this->metrics !== null) {
            $this->metrics->lookups++;
        }

        $headers = "User-Agent: " . self::USER_AGENT . "\r\nAccept: application/json\r\n";
        if ($this->token !== null && $this->token !== '') {
            $headers .= "Authorization: Bearer " . $this->token . "\r\n";
        }

        $context = stream_context_create([
            'http' => [
                'method' => 'GET',
                'protocol_version' => 1.1,
                'timeout' => $this->timeoutSeconds,
                'follow_location' => 0,
                'ignore_errors' => true,
                'header' => $headers . "Connection: keep-alive\r\n",
            ],
        ]);

        $body = @file_get_contents($url, false, $context);
        if ($body === false) {
            if ($this->metrics !== null) {
                $this->metrics->apiErrors++;
            }
            return [
                'success' => false,
                'networkName' => null,
                'country' => null,
                'countryCode' => null,
                'countryName' => null,
                'error' => 'request_failed',
            ];
        }

        $statusCode = $this->extractStatusCode($http_response_header ?? []);
        if ($statusCode < 200 || $statusCode >= 300) {
            if ($this->metrics !== null) {
                $this->metrics->apiErrors++;
            }
            return [
                'success' => false,
                'networkName' => null,
                'country' => null,
                'countryCode' => null,
                'countryName' => null,
                'error' => 'http_' . $statusCode,
            ];
        }

        $decoded = json_decode($body, true);
        if (!is_array($decoded)) {
            if ($this->metrics !== null) {
                $this->metrics->apiErrors++;
            }
            return [
                'success' => false,
                'networkName' => null,
                'country' => null,
                'countryCode' => null,
                'countryName' => null,
                'error' => 'invalid_json',
            ];
        }

        $networkName = $this->extractNetworkName($decoded);
        if ($networkName === null) {
            if ($this->metrics !== null) {
                $this->metrics->apiErrors++;
            }
            return [
                'success' => false,
                'networkName' => null,
                'country' => null,
                'countryCode' => null,
                'countryName' => null,
                'error' => 'missing_network_name',
            ];
        }

        $countryCode = $this->extractCountryCode($decoded);
        $countryName = $this->extractCountryName($decoded);
        $country = $countryName ?? $countryCode;

        return [
            'success' => true,
            'networkName' => $networkName,
            'country' => $country,
            'countryCode' => $countryCode,
            'countryName' => $countryName,
            'error' => null,
        ];
    }

    public function isRateLimited(): bool
    {
        if ($this->rateLimit <= 0) {
            return true;
        }

        $this->pruneApiCallTimestamps(microtime(true));
        return count($this->apiCallTimestamps) >= $this->rateLimit;
    }

    public function getRateLimitRetryAfterMs(): int
    {
        if ($this->rateLimit <= 0) {
            return 60_000;
        }

        $now = microtime(true);
        $this->pruneApiCallTimestamps($now);

        if ($this->apiCallTimestamps === []) {
            return 100;
        }

        $oldestTimestamp = $this->apiCallTimestamps[0];
        return max(100, (int) ceil(max(0.0, (60.0 - ($now - $oldestTimestamp)) * 1000)));
    }

    /**
     * @param array<int, string> $responseHeaders
     */
    private function extractStatusCode(array $responseHeaders): int
    {
        foreach ($responseHeaders as $headerLine) {
            if (preg_match('/^HTTP\/\S+\s+(\d{3})\b/', $headerLine, $matches) === 1) {
                return (int) $matches[1];
            }
        }
        return 0;
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function extractNetworkName(array $payload): ?string
    {
        $asnName = null;
        if (isset($payload['asn']) && is_array($payload['asn']) && isset($payload['asn']['name']) && is_string($payload['asn']['name'])) {
            $asnName = trim($payload['asn']['name']);
        }

        if ($asnName !== null && $asnName !== '') {
            return $asnName;
        }

        $org = isset($payload['org']) && is_string($payload['org']) ? trim($payload['org']) : '';
        if ($org === '') {
            return null;
        }

        $withoutAsnNumber = preg_replace('/^AS\d+\s+/i', '', $org);
        $withoutAsnNumber = is_string($withoutAsnNumber) ? trim($withoutAsnNumber) : '';

        return $withoutAsnNumber !== '' ? $withoutAsnNumber : $org;
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function extractCountryName(array $payload): ?string
    {
        $countryName = isset($payload['country_name']) && is_string($payload['country_name']) ? trim($payload['country_name']) : '';
        if ($countryName !== '') {
            return $countryName;
        }

        $countryCode = $this->extractCountryCode($payload);
        if ($countryCode === null) {
            return null;
        }

        $normalizedCode = strtoupper($countryCode);
        return $this->countryCodeToName[$normalizedCode] ?? null;
    }

    /**
     * @return array<string, string>
     */
    private function loadCountries(string $path): array
    {
        $contents = @file_get_contents($path);
        if ($contents === false) {
            return [];
        }

        $decoded = json_decode($contents, true);
        if (!is_array($decoded)) {
            return [];
        }

        $countries = [];
        foreach ($decoded as $code => $name) {
            if (is_string($code) && is_string($name)) {
                $countries[strtoupper(trim($code))] = trim($name);
            }
        }

        return $countries;
    }

    private function pruneApiCallTimestamps(float $now): void
    {
        $this->apiCallTimestamps = array_values(array_filter(
            $this->apiCallTimestamps,
            static fn (float $timestamp): bool => ($now - $timestamp) < 60.0
        ));
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function extractCountryCode(array $payload): ?string
    {
        $countryCode = isset($payload['country']) && is_string($payload['country']) ? trim($payload['country']) : '';
        return $countryCode !== '' ? $countryCode : null;
    }
}
