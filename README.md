# JunkVPN

An Android app that finds the fastest working **Cloudflare WARP** endpoints for
your network, registers a WARP device account, and exports ready-to-import
**WireGuard** / **AmneziaWG** tunnel configs.

The heavy lifting lives in a Go core compiled to Android native code with
gomobile; the UI is a fresh Material 3 design written in Jetpack Compose.
All code in this repository is original.

> Concept inspired by WARP endpoint scanning tools such as
> [openwarpkit/warpscout-android](https://github.com/openwarpkit/warpscout-android).
> No code was reused — the scanner, protocol handling, and UI are written from
> scratch here.

## Features

- **Endpoint scanner** — probes public Cloudflare WARP anycast ranges with
  three presets (Quick / Standard / Deep), or your own custom targets.
- **Dual probe design** — a *real WireGuard handshake* over UDP measures true
  tunnel RTT; when UDP is filtered, a TCP connect to port 443 proves the edge
  is alive. Handshake-confirmed endpoints always rank first.
- **Live results** — progress, per-endpoint latency, jitter, and loss stream
  into the UI while the scan runs.
- **Identity verification** — one tap proves an endpoint will actually accept
  *your* account: the app completes a full WireGuard handshake with the
  registered keys, and only a peer holding the real WARP private key answers
  with a valid authenticator. Works per endpoint and for the best pick.
- **WARP account** — registers a device through the public WARP API. The
  private key is generated on-device and stored **encrypted with the Android
  Keystore**; only the public key is sent to Cloudflare.
- **Registration on blocked networks** — networks that firewall the WARP API
  don't stop you: the register request can be routed through a SOCKS5/HTTP
  proxy (Settings → Registration, including local ports exposed by other VPN
  apps), and instead of trusting a single resolved IP it retries every
  system **and DNS-over-HTTPS** answer for the API host (IPv4 and IPv6).
  Failures show exactly which addresses were tried plus how to work around
  the block — register once on another network and the account keeps
  working on the blocked one.
- **Config export** — one tap to copy/share a standard WireGuard `.conf`, or
  an AmneziaWG variant with obfuscation parameters (Jc/Jmin/Jmax/S1/S2).
- **History** — the last 30 scans are saved locally with their top results.
- **Theme** — Material 3 Expressive design with system/light/dark modes.

## How the scanning works

| Preset    | Targets | Probes | Timeout | Workers |
| --------- | ------- | ------ | ------- | ------- |
| `quick`   | 64      | 1      | 1.0 s   | 32      |
| `standard`| 256     | 2      | 1.5 s   | 64      |
| `deep`    | 1024    | 3      | 2.0 s   | 96      |

1. Random addresses are drawn from the consumer WARP ranges
   (`162.159.192/193/195.0/24`, `188.114.96–99.0/24`) across the usual
   WireGuard ports (2408, 500, 4500, 1701).
2. Each candidate gets a real WireGuard handshake attempt — a valid reply
   means a live, usable endpoint and yields a true RTT. When a WARP account
   is registered, probes use its identity, so edges that only answer
   registered keys respond to the scan.
3. If the handshake fails, a TCP connect to port 443 is measured as a
   reachability fallback (marked `TCP` in the results).
4. Results are ranked: `WG` confirmed first by RTT, then `TCP` reachable.

## Architecture

```
JunkVPN/
├── warpcore/            Go core — scanning, WireGuard handshakes, WARP API, config rendering
│   ├── scan.go          target expansion, worker pool, ranking
│   ├── wireguard.go     Noise-ish handshake built on BLAKE2s + Curve25519
│   ├── probe.go         UDP handshake + TCP connect probes, jitter/loss stats
│   ├── verify.go        account identity verification (authenticated handshake)
│   ├── warpapi.go       WARP device registration client
│   ├── wgconfig.go      WireGuard / AmneziaWG config rendering
│   └── *_test.go        unit tests + end-to-end handshake vs. wireguard-go
├── android/             Jetpack Compose app (package com.junkvpn.app)
│   └── app/src/main/java/com/junkvpn/app/
│       ├── core/        WarpBridge (gomobile bindings) + result models
│       ├── data/        ScanRepository, Keystore-encrypted account, history, settings
│       └── ui/          theme, navigation, Scan/History/Account/Settings screens
├── scripts/build-core.ps1   builds warpcore.aar with gomobile
└── tools/probecheck/        CLI diagnostic that probes endpoints from a desktop
```

The Go core exposes a small JSON-based API (`NewScan`, `RegisterAccount`,
`BuildConfig`, `PresetConfig`) through gomobile; the Kotlin layer wraps it in
coroutines and exposes one `StateFlow` per screen.

## Building

### Prerequisites

- JDK 17+ (21 recommended)
- Android SDK with **API 37** platform + Build-Tools, NDK (28.2+ recommended)
- Gradle 9.6+ (wrapper included) — or let Android Studio supply it
- Go 1.21+ and gomobile for the native core:
  ```
  go install golang.org/x/mobile/cmd/gomobile@latest
  ```

### 1. Build the native core

```powershell
./scripts/build-core.ps1      # -> android/app/libs/warpcore.aar
```

### 2. Build the app

```powershell
cd android
./gradlew :app:assembleDebug          # debug APK
./gradlew :app:assembleRelease        # R8-minified, unsigned APK
```

The APK lands in `android/app/build/outputs/apk/`. To deploy to a connected
device: `./gradlew :app:installDebug`.

### Run the Go tests

```powershell
go test ./...
```

The suite includes a full end-to-end handshake test against a real
`wireguard-go` responder, so the wire format is verified without a device.

## Privacy

- No analytics, no telemetry, no accounts on our side.
- Scan history, settings, and the encrypted WARP identity never leave the
  device (registration talks only to `api.cloudflareclient.com`).
- The optional registration proxy carries only the register request;
  scanning and the tunnel never use it.
- If system DNS fails during registration, the API host is re-resolved via
  DNS-over-HTTPS (1.1.1.1 / 8.8.8.8) as a second opinion — that lookup
  sends only the API hostname, never anything else.
- Scanning sends UDP/TCP probes to Cloudflare anycast addresses only.

## Disclaimer

JunkVPN is an independent, open-source tool. It is **not** affiliated with,
endorsed by, or connected to Cloudflare, Inc. Use it in accordance with the
Cloudflare Terms of Service and the laws that apply to you.

## License

[MIT](LICENSE)
