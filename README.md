# AA Guard

![AA Guard logo](logo.png)

AA Guard watches ladderlog input and writes server commands.
It is small, no external PHP packages, built for long-running pipe use.

## Quick Story

Player joins > guard reads event > guard checks IP at ipinfo.io >
guard resolves network/country > guard optionally emits join notification >
guard compares network against regex rules > guard executes action templates if matched.

## Features

- Reads `STDIN` line by line (non-blocking loop with `stream_select`).
- Writes command output to `STDOUT` and flushes immediately.
- Writes logs to `STDERR` with level (`DEBUG`, `WARN`, `ERROR`).
- Handles `PLAYER_ENTERED_GRID` event.
- Parses display name even when it has spaces.
- Validates IPv4 format before processing event.
- Uses ipinfo.io lookup for:
  - network/as name,
  - country code,
  - country name.
- Supports `IPINFO_TOKEN` via Bearer auth.
- Supports API timeout config.
- Supports local rate limit per minute for outbound API calls.
- Uses in-memory IP cache (`cacheTtlSeconds`).
- Uses retry queue with custom delays (`retry.delaysMs`); when rate limited by ipinfo.io, overrides delays with rate limit backoff.
- Uses action dedupe window (`dedupeWindowSeconds`) to reduce repeated punishments.
- Matches network name with regex rules (`rules[].pattern`).
- Validates regex rules at startup (invalid regex stops process).
- Supports startup actions (`actions.onStartup`).
- Supports join actions (`actions.onConnect`) and custom join message template (`actions.onConnectMessage`).
- Supports match actions (`actions.onMatch`).
- Supports metrics actions (`actions.onMetrics`).
- Supports debug-forward actions (`actions.onDebug`) when `debug=true`.
- Guarantees per-admin join notice even if `actions.onConnect` forgot `{{admin}}` template.
- Tracks metrics:
  - bans,
  - lookups,
  - cache hits,
  - API errors,
  - rate-limited events,
  - invalid IPs,
  - runtime.
- Periodic metrics report (`metricsIntervalSeconds`, `0` = off).
- Manual metrics trigger with signal `SIGUSR1`.
- Graceful stop on `SIGTERM` / `SIGINT`.
- Stops cleanly if `STDIN` closes.

## Requirements

- PHP `8.1+`
- Access to `https://ipinfo.io`
- Armagetron server with `ladderlog.txt` support (min `0.2.8-sty` or `0.4`)

Recommended server pipeline shape:

```sh
tail -fn0 -s0.01 /path/to/commands_file | $armagetron-dedicated | tee -a /path/to/console_log
```

## Run

Default config:

```sh
tail -fn0 -s0.01 /path/to/server_ladderlog | php /path/to/aa-guard/bin/aa_guard.php | tee -a /path/to/commands_file
```

Custom config path:

```sh
tail -fn0 -s0.01 /path/to/server_ladderlog | php /path/to/aa-guard/bin/aa_guard.php /path/to/config_dir | tee -a /path/to/commands_file
```

Detached `screen` + token:

```sh
IPINFO_TOKEN="your_token" screen -dmS aa-guard sh -c 'tail -fn0 -s0.01 /path/to/server_ladderlog | php /path/to/aa-guard/bin/aa_guard.php /path/to/config_dir | tee -a /path/to/commands_file'
```

## Runtime Control

- `SIGTERM`: stop
- `SIGINT`: stop
- `SIGUSR1`: send metrics now (if `pcntl` signals available)

## Config Files

Default path: `config/`

- `config/general.json`: general settings
- `config/actions.json`: action templates
- `config/rules.json`: match rules

Legacy single-file config still works if you pass JSON file path explicitly.

### `general.json` keys

- `admins` (array, required)
- `retry.maxAttempts` (int, required)
- `retry.delaysMs` (int array, required)
- `cacheTtlSeconds` (int, default `1800`)
- `dedupeWindowSeconds` (int, default `15`)
- `ipInfoTimeoutSeconds` (int, default `2`)
- `ipInfoRateLimitPerMinute` (int, default `30`)
- `metricsIntervalSeconds` (int, default `0`)
- `debug` (bool, default `false`)

### `actions.json` keys

- `onStartup` (array, required): executed once at startup
- `onDebug` (array, required): templates for debug output (only emitted when `debug=true`; each log event sent to each admin)
- `onConnectMessage` (string, required): template that generates `{{msg}}` placeholder for join notices (uses player_id, country_name, country_code, network_name context)
- `onConnect` (array, required): action templates for each player join (can include `{{msg}}` from onConnectMessage)
- `onMatch` (array, required): action templates when player network matches a rule
- `onMetrics` (array, optional, default `[]`): templates for metrics report (emitted periodically or on SIGUSR1)

### `rules.json`

Array of rule objects. Each item:

- `name` (non-empty string)
- `pattern` (non-empty valid regex)

## Template System

### `actions.onConnectMessage`

Template that builds the `{{msg}}` placeholder. Rendered **before** `onConnect` templates execute.

Available placeholders:
- `{{player_id}}`
- `{{country_name}}`
- `{{country_code}}`
- `{{network_name}}`

Example: `"{{player_id}} is connecting from {{country_name}} ({{country_code}}), network: {{network_name}}."`

### `actions.onConnect`

Action templates executed for each player join. Have access to:
- `{{msg}}` (rendered from `onConnectMessage`)
- `{{player_id}}`
- `{{country}}` / `{{country_name}}` / `{{country_code}}`
- `{{network_name}}`
- `{{admin}}` (only in templates targeting admin)

Behavior:
- Template with `{{admin}}`: emitted once per admin in `admins` array
- Template without `{{admin}}`: emitted once per join
- If no admin-targeted template exists, guard auto-sends: `PLAYER_MESSAGE {{admin}} "{{msg}}"`

### `actions.onMatch`

- `{{player_id}}`
- `{{display_name}}`
- `{{ip}}`
- `{{country}}`
- `{{network_name}}`
- `{{rule_name}}`

### `actions.onMetrics`

- `{{admin}}`
- `{{bans}}`
- `{{lookups}}`
- `{{cache_hits}}`
- `{{api_errors}}`
- `{{rate_limited}}`
- `{{invalid_ips}}`
- `{{runtime}}`

### `actions.onDebug` (used only when `debug=true`)

- Usually static commands, placeholders not required.

## Default join message

Default `{{msg}}` format from `actions.onConnectMessage`:

```txt
<player_id> is connecting from <country_name> (<country_code>), network: <network_name>.
```

## Accepted ladderlog line

```txt
PLAYER_ENTERED_GRID player_1 192.168.51.42 Player 1
```

## Full Example Config

```json
{
  "actions": {
    "onStartup": [
      "CONSOLE_MESSAGE 0xff0000>> 0x888888[GUARD] 0xffffff AA guard started"
    ],
    "onDebug": [
      "PLAYER_MESSAGE {{admin}} \"0xff0000>> 0x888888[GUARD] 0xffffff [{{level}}] {{msg}}\""
    ],
    "onConnectMessage": "{{player_id}} is connecting from {{country_name}} ({{country_code}}), network: {{network_name}}.",
    "onConnect": [
      "# CONSOLE_MESSAGE 0xff0000>> 0x888888[GUARD] 0xffffff{{player_id}} is connecting from {{country_name}} ({{country_code}}).",
      "PLAYER_MESSAGE {{admin}} \"0xff0000>> 0x888888[GUARD] 0xffffff {{msg}}\""
    ],
    "onMatch": [
      "KICK {{player_id}} Your network is banned.",
      "CONSOLE_MESSAGE 0xff0000>> 0x888888[GUARD] 0xffffff {{player_id}} was kicked because {{rule_name}} networks are banned."
    ],
    "onMetrics": [
      "PLAYER_MESSAGE {{admin}} \"0xff0000>> 0x888888[GUARD] 0xffffff bans={{bans}} lookups={{lookups}} cacheHits={{cache_hits}} apiErrors={{api_errors}} rateLimited={{rate_limited}} invalidIps={{invalid_ips}} runtime={{runtime}}\""
    ]
  },
  "admins": [
    "admin_1",
    "admin_2"
  ],
  "rules": [
    {
      "name": "vpn",
      "pattern": "/vpn/i"
    }
  ],
  "retry": {
    "maxAttempts": 3,
    "delaysMs": [250, 750, 1500]
  },
  "cacheTtlSeconds": 1800,
  "dedupeWindowSeconds": 15,
  "ipInfoTimeoutSeconds": 2,
  "ipInfoRateLimitPerMinute": 30,
  "metricsIntervalSeconds": 300,
  "debug": false
}
```

## Notes (Important)

- Config loader exits with code `2` on invalid/missing config fields.
- Guard exits with code `1` if `stream_select` fails.
- Lookup rejects private/reserved IP ranges in ipinfo client (`private_ip` error).
- Invalid IPv4 format is dropped early and increments `invalid_ips` metric.
- Dedupe key is `playerId|ruleName`.
- No external dependency manager needed.
- **Retry mechanism**: Triggered by IP lookup failure or rate limiting. Configured delays (`retry.delaysMs`) apply to lookup failures; rate limiting uses ipinfo.io's backoff timing instead.
- **Template value sanitization**: Values like `{{player_id}}` are sanitized (alphanumeric + spaces/slashes/dashes/dots/underscores/@); `{{msg}}` in quoted contexts uses quoted escaping (`\"` and `\\`).
- **Admin-targeted actions**: Templates with `{{admin}}` placeholder are emitted once per admin; useful for debug, metrics, and targeted join notices.

```text
[ EOF ]  keep server clean, keep grid fair, keep logs loud.
```
