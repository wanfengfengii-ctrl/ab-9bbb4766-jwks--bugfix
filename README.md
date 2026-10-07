# Calibration Evidence Bundle Service

Metrology labs hand partner organizations **short-lived, proof-of-possession**
access to calibration evidence packs. A leaked access token is useless on its
own: every download must additionally be signed by the caller key that the
token is cryptographically bound to, and each signed proof may be presented
**exactly once** — even across server restarts and under concurrent requests.

## What it does

```
GET /api/calibration-bundles/{bundleId}
Authorization: DPoP <ES256 access-token JWT>
DPoP:          <ES256 DPoP proof JWT>
```

- Success: `200` with the raw, byte-concatenated evidence (files 1..N in
  configured number order) and digest headers:
  - `X-Bundle-SHA-256` — lowercase hex SHA-256 of the complete response body;
  - `Digest: sha-256=<base64url>` — RFC 3230 form of the same digest;
  - `X-Evidence-SHA-256-<n>` — the configured lowercase hex digest per file;
  - `ETag`, `Content-Length`, `Content-Disposition`, `Cache-Control: no-store`.
- Every other outcome is a stable JSON error code
  (`{"error":"...","error_description":"..."}`):

  | HTTP | error code             | meaning                                        |
  |------|------------------------|------------------------------------------------|
  | 401  | `malformed_request`    | missing/malformed credentials                  |
  | 401  | `invalid_token`        | signature, `iss`/`aud`/`sub`/`cnf` failure     |
  | 401  | `expired_token`        | access token outside `nbf`/`exp`               |
  | 403  | `insufficient_scope`   | missing `bundles:read`                         |
  | 401  | `invalid_dpop_proof`   | proof signature, binding, typ, jti, iat, htm, htu or ath failure |
  | 409  | `replay_detected`      | proof `jti` was already consumed (incl. after restart) |
  | 404  | `bundle_not_found`     | unknown bundle id                              |

### Access token validation

Registered issuer ES256 public JWK; verified claims: `alg=ES256`, `iss`,
`aud` (string or array), `sub`, `exp`/`nbf` (with leeway), `scope`/`permissions`
containing `bundles:read`, and `cnf.jkt` (RFC 7638 SHA-256 thumbprint of the
caller key).

### DPoP proof validation (RFC 9449, ES256)

- protected header: `typ=dpop+jwt`, `alg=ES256`, inline public `jwk`
  (signature verified against that exact key; `kid` rejected);
- `cnf.jkt == SHA-256 thumbprint(jwk)` — the proof key is the token-bound key;
- `jti` present, `iat` within the configured short lifetime (default 60 s) with
  skew leeway; optional `exp`/`nbf` honored;
- `htm == GET`;
- `htu` must equal **exactly** `PUBLIC_ORIGIN + /api/calibration-bundles/{id}`
  built from the configured public origin — internal hostnames, trailing
  slashes and casing variants are rejected;
- `ath == base64url(SHA-256(access token))` — the proof binds this token.

### Single-use enforcement

Accepted `jti`s are atomically claimed against an in-process mutex and
immediately appended with `fsync` to
`${REPLAY_DIR}/used-jti.log` (exclusive `flock`). The log is replayed at
startup, so:

- concurrent requests sharing one proof produce exactly **one** `200` and
  `n-1` × `409 replay_detected`;
- the same proof is rejected after a process restart;
- evidence bytes are only streamed after the durable claim succeeds.

## Layout

```
cmd/keygen   one-shot provisioning: issuer key + manifest (computes digests)
cmd/server   the resource server
cmd/verify   one-shot acceptance: waits healthy, go test + build, then
             download / tamper / concurrency / restart-replay smoke tests
internal/    jwx (ES256/JWK/JWT), config, auth, store, server, minting
examples/    demo evidence files (01-…,02-…,03-…, read-only)
```

There are **no third-party Go modules**; everything is stdlib.

## Clean-station deployment (Docker Compose)

```bash
HOST_PORT=9090 docker compose up --build
# verify result:
docker compose ps
docker compose logs verify     # exits 0 ("VERIFY OK") or non-zero
```

1. `keygen` runs once: creates the issuer JWK pair in a volume and renders
   `/etc/calibration/config.json` from the read-only evidence mount;
2. `calibration-server` starts after keygen, is health-checked on
   `/healthz`, and publishes `${HOST_PORT:-8080}:8080`;
3. `verify` starts only after the server is healthy, runs unit tests + build
   and the live smoke suite, prints a PASS/FAIL summary, and exits with the
   result code (restart: "no").

Replays stay rejected across `docker compose restart` thanks to the
`cal-replay` volume; wipe it (`docker compose down -v`) for a clean station.

### Configuration

Manifest (rendered by keygen; can also be hand-authored):

```json
{
  "public_origin": "https://api.met-lab.example",
  "issuer": "https://issuer.met-lab.example",
  "audience": "calibration-bundles-api",
  "subject": "partner-lab-alpha",
  "issuer_jwk_path": "/secrets/issuer/jwk.json",
  "access_leeway_seconds": 30,
  "dpop_max_age_seconds": 60,
  "dpop_leeway_seconds": 30,
  "bundles": [
    {"id": "B-2026-0042", "files": [
      {"number": 1, "path": "/evidence/01-report.txt",      "sha256": "…lowercase hex…"},
      {"number": 2, "path": "/evidence/02-readings.bin",    "sha256": "…"}
    ]}
  ]
}
```

Rules enforced at load: 1–8 files per bundle, numbers 1–8 unique, digests are
64 lowercase hex chars matching the on-disk content, evidence must be regular
non-symlink files without any write bit. Env overrides: `PUBLIC_ORIGIN`,
`ISSUER`, `AUDIENCE`, `SUBJECT`, `ISSUER_JWK_PATH`, `LISTEN_ADDR`/`PORT`,
`CONFIG_PATH`, `REPLAY_DIR`.

## Local development

```bash
go test ./...                                  # unit tests
go run ./cmd/keygen   --keys-dir=/tmp/k \
    --config=/tmp/c/config.json --evidence-dir=./examples/evidence
go run ./cmd/server   --config /tmp/c/config.json            # :8080
go run ./cmd/verify   --config /tmp/c/config.json \
    --issuer-key /tmp/k/jwk-private.json \
    --base-url http://127.0.0.1:8080 --src-dir .
```
