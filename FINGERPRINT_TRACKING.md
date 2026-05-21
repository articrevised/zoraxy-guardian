# Fingerprint Tracking Feature

## Overview

Guardian now tracks **request fingerprints** to identify and block malicious actors **across IP changes**. This catches attackers who rotate IPs or use distributed scanners with identical tooling.

## How It Works

### 1. Fingerprint Generation
Each request gets a fingerprint hash based on:
- **User-Agent** header
- **Accept** headers (content type, encoding, language)
- **HTTP version** (HTTP/1.1, HTTP/2, etc.)

These characteristics are normalized (lowercase, sorted) and hashed to a 16-character hex string for compact storage.

### 2. Strike Tracking
When any Guardian rule blocks a request:
- IP gets a strike (existing behavior)
- **Fingerprint also gets a strike** (new)

Strikes are tracked in a rolling time window (configurable).

### 3. Auto-Ban Escalation
When a fingerprint accumulates **Threshold** strikes within **Window** seconds:
- The fingerprint is added to the ban list for **Ban duration** seconds
- **All future requests with that fingerprint are blocked**, regardless of source IP

This is evaluated **before** IP-based rules, so an attacker rotating through fresh IPs still gets caught.

## Configuration

Located in the **Fingerprint** tab:

| Setting | Default | Description |
|---------|---------|-------------|
| **Enabled** | OFF | Toggle fingerprint tracking |
| **Threshold** | 10 strikes | How many blocks before fingerprint is banned |
| **Window** | 300 sec (5 min) | Rolling window for counting strikes |
| **Ban duration** | 3600 sec (1 hr) | How long the fingerprint stays banned |

**Defaults are intentionally higher than IP auto-ban** (10 vs 5 threshold, 1 hour vs 10 min ban) because fingerprints are less precise than IPs — you don't want to accidentally block an entire browser version.

## Use Cases

### Perfect For:
- **Rotating-proxy scanners** (same tool, different IPs every request)
- **Distributed botnets** using identical tooling
- **Persistent attackers** who manually rotate through VPN endpoints
- **Cloud scanner services** (Shodan, Censys, etc.) with large IP pools

### Example Attack Pattern
```
13:00:01 | 1.2.3.4     | fp:a1b2c3d4e5f6g7h8 | SQLi attempt → BLOCK (strike 1)
13:00:05 | 5.6.7.8     | fp:a1b2c3d4e5f6g7h8 | XSS attempt → BLOCK (strike 2)
13:00:12 | 9.10.11.12  | fp:a1b2c3d4e5f6g7h8 | Path traversal → BLOCK (strike 3)
...
13:04:50 | 21.22.23.24 | fp:a1b2c3d4e5f6g7h8 | UA block → BLOCK (strike 10)
→ Fingerprint a1b2c3d4e5f6g7h8 BANNED for 1 hour
13:05:01 | 25.26.27.28 | fp:a1b2c3d4e5f6g7h8 | ANY request → BLOCKED (fingerprint-ban)
```

Without fingerprint tracking, each IP would be evaluated independently and the attack could continue indefinitely.

## UI Features

### Block Log
When fingerprint tracking is enabled, the block log shows the fingerprint hash for each entry:

```
Time                 | IP            | FP (truncated)    | Reason
2026-05-21 07:15:32 | 1.2.3.4       | a1b2...f6g7h8     | waf-sqli
2026-05-21 07:15:45 | 5.6.7.8       | a1b2...f6g7h8     | ua-blocklist
2026-05-21 07:18:10 | 9.10.11.12    | a1b2...f6g7h8     | fingerprint-ban ← FINGERPRINT BLOCKED
```

### Fingerprint Tab
Shows currently banned fingerprints with expiry times. Each entry has a **Clear** button to manually revoke the ban.

## API Endpoints

### GET `/api/fingerprintbans`
Returns list of currently banned fingerprints:
```json
[
  {
    "fingerprint": "a1b2c3d4e5f6g7h8",
    "expires": "2026-05-21T08:15:32Z"
  }
]
```

### POST `/api/fingerprintbans/clear?fingerprint=<hash>`
Removes a fingerprint from the ban list immediately.

## Technical Details

### Storage
- Fingerprint bans: `map[string]time.Time` (fingerprint → expiry)
- Fingerprint strikes: `map[string][]time.Time` (fingerprint → timestamps)
- Auto-cleaned every 60 seconds (expired bans + stale strikes)

### Performance
- Fingerprint generation: ~2µs per request (SHA256 + string ops)
- Memory overhead: ~100 bytes per tracked fingerprint
- Sweep cost: O(n) where n = active fingerprints (typically < 1000)

### Config File
New `fingerprint_tracking` section in `config.json`:
```json
{
  "fingerprint_tracking": {
    "enabled": false,
    "threshold": 10,
    "window_seconds": 300,
    "ban_seconds": 3600
  }
}
```

Backfilled with defaults on load for existing installations.

## Limitations

### False Positives
Fingerprints are **less specific than IPs**:
- Many users share the same User-Agent + Accept headers
- Corporate networks with identical browser configs can share fingerprints
- **Mitigation**: Use higher threshold (10+) and shorter ban durations initially

### Evasion
Attackers can evade by:
- Randomizing User-Agent strings
- Varying Accept headers between requests
- Mixing HTTP/1.1 and HTTP/2
- **Defense in depth**: Fingerprinting complements IP rules, not replaces them

### Legitimate Tool Blocking
Automated tools (CI runners, monitoring services, RSS readers) often share fingerprints across many IPs. Add their paths to **UA rule exceptions** or their IPs to the allowlist.

## Recommendations

1. **Start with it disabled**, monitor the block log to see how many unique fingerprints appear
2. **Enable with high threshold** (15-20) to catch only the most aggressive actors
3. **Lower threshold gradually** as you verify no false positives
4. **Combine with honeypots** for instant signal on malicious fingerprints
5. **Use shorter ban durations** (15-30 min) if you're worried about false positives

## Future Enhancements

- Export fingerprint ban list for sharing across Guardian instances
- Whitelist known-good fingerprints (e.g., monitoring tools)
- Show fingerprint-to-IP mappings in the UI
- Fingerprint-based rate limiting (separate from IP-based)
