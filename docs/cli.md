# Run it end to end from the CLI

Everything the [dashboard](dashboard.md) does is also available from the command line. Follow these steps in order.

## 1. Prerequisites

- Node.js 22 or later, and pnpm (`corepack enable`)
- A Helius API key from [dashboard.helius.dev](https://dashboard.helius.dev), with access to Parsed Events and Parsed Streams

## 2. Install, build and test

```sh
git clone https://github.com/helius-labs/watchtower
cd watchtower
pnpm install
pnpm check   # format, lint, typecheck, tests, build
```

The tests run offline and never spend API credits. They include Squads v3 and v4 decoding against real mainnet accounts (Jupiter's and Kamino's upgrade multisigs).

## 3. Set up a program

```sh
cp .env.example .env      # then set HELIUS_API_KEY in .env
pnpm dev init
```

`init` reads your key from `.env` and asks for:

| Prompt                  | Example                                                                  |
| ----------------------- | ------------------------------------------------------------------------ |
| Program ID              | `KLend2g3cP87fffoy8q1mQqGKjrxjC8boSyAYavgmjD` (Kamino Lend)              |
| Admin-only instructions | pre-selected from the program's IDL; press enter to accept               |
| Mints to watch          | `J1toso1uCk3RLmjorhTtrVwY9HJ7X8V9yYac6Y7kGCPn` (JitoSOL, used in step 7) |
| Alert channels          | optional: Discord, Slack, Telegram, webhook                              |

Watchtower then reads the program's ProgramData account and finds the upgrade authority. If the authority is a Squads vault, it finds the multisig through the vault's Parsed Events history and confirms it by re-deriving the vault address:

```
◇  Discovered
│  Program data   9uSbGW1y9H5Av6H5TKxQ1wnFApSq2t3oEpfF2YfjDQGA
│  Authority      Squads v4 vault GzFgdRJXmawPhGeBsyRCDLx4jAKPsvbUqoqitzppkzkW
│  Multisig       6hhBGCtmg7tPWUSgp3LG6X2rsmYWAc4tNsA6G4CnfQbM
│  Threshold      5 of 10, time lock 86400s
```

This writes `watchtower.yaml` (see [`watchtower.example.yaml`](../watchtower.example.yaml)). Any alert-channel secrets are added to `.env`, which stays mode 600 and git-ignored.

## 4. Check alert delivery

```sh
pnpm dev test-alert
```

This sends one sample critical alert to every configured channel. Fix any `Alert delivery failed` line before continuing.

## 5. Generate the posture report

```sh
pnpm dev report
open reports/watchtower-*.html
```

The first run scans 90 days of history for each watched address and records it without alerting. The terminal output and HTML report show:

- **Posture grade:** one per subject (program, multisig, mint), with the overall grade taken from the weakest subject; see [how the grade works](grading.md)
- **Activity:** every finding in the window
- **Coverage:** transactions scanned, matches and credits used, per scan. A scan that hit its budget is marked **Recent only** or **Behind**; see [how alerts stay complete](detectors.md#how-alerts-stay-complete)

## 6. Start live monitoring

```sh
pnpm dev watch
```

Expected output:

```
14:02:11 Watchtower watching 1 program(s), 1 multisig(s), 1 mint(s)
14:02:11   Stream deployments: BPF loader, 1 account
14:02:12 Connected to Parsed Streams
14:02:12 Backfilling up to slot 464,612,034 with Parsed Events…
14:02:14   Kamino Lend deployments: 3 scanned, 0 new finding(s). Up to date: Every transaction in the window was scanned.
```

On each connect, `watch`:

1. Subscribes to Parsed Streams.
2. Delivers any alerts that `report` queued or that previously failed to send.
3. Scans from each saved cursor to the current slot, so nothing that happened while it was stopped is missed.
4. Moves the cursors forward as notifications arrive, once each one is processed.
5. Every 5 minutes, logs a heartbeat with the notifications received per subscription, so a quiet stream can be told apart from a broken one.

## 7. See a live alert

Program upgrades and multisig changes are rare. To see the pipeline fire within minutes, watch a high-traffic mint at `info` severity. JitoSOL mints new tokens on every stake deposit.

In `watchtower.yaml`, set the console sink to show everything:

```yaml
alerts:
  minSeverity: low
  sinks:
    - type: console
      minSeverity: info
```

Restart `pnpm dev watch`. Within a few minutes you should see:

```
 INFO  Tokens minted · JitoSOL · slot 464612301
  1.92 JitoSOL minted (0.00% of supply at discovery).
  https://orbmarkets.io/tx/…
```

## 8. Confirm gap-fill

Stop `watch` with Ctrl+C, wait two minutes, and start it again. The backfill lines report the transactions it missed while stopped, and their findings print as alerts.

## 9. Run it unattended

```sh
docker build -t watchtower .
docker run -d --name watchtower --restart unless-stopped -v "$PWD:/data" watchtower watch
docker logs -f watchtower
```

The container reads `watchtower.yaml` and `.env` from the mounted directory and keeps its state in `.watchtower/` there. Without `watch`, the image runs the dashboard instead; see [hosting](dashboard.md#host-your-own-dashboard).

To start over from scratch, delete `.watchtower/state.json`.

## 10. Replay an exploit

`replay` runs every detector over a past window with Parsed Events and prints a timeline. It never sends alerts or touches your state file. With `--program`, no config is needed: admin instructions come from the IDL that was live when the window starts.

```sh
pnpm dev replay --program dRiftyHA39MWEi3m9aunc5MzRF1JYuBsbn6VPcn33UH:Drift \
  --from 2026-03-20 --to 2026-04-02 --no-program-scans
```

`--no-program-scans` skips scanning the program's whole transaction stream, which for a busy program runs to millions of transactions a day. Admin calls are still found through each admin key's own, much shorter history. `--budget` caps each scan, and `--json` saves the findings.

After the timeline, **Detector coverage** says what each detector covered, so a quiet replay isn't mistaken for a clean one:

| Status             | Meaning                                                                                                                                                                                                                    |
| ------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ran`              | Every scan feeding it reached the end of the window.                                                                                                                                                                       |
| `missing data`     | Part of its input wasn't scanned: a scan stopped at `--budget`, `--no-program-scans` skipped the program-wide admin scan, or a program has no known admin instructions. The reason names which.                            |
| `nothing to watch` | Discovery found nothing of its kind, such as no mints or vaults.                                                                                                                                                           |
| `live only`        | It can't run on past data: `config-change` needs past account states, which RPC doesn't serve; `nonce-authority` watches nonce instructions chain-wide; `build-verification` rechecks upgrades 30 minutes after they land. |

`idl-change` runs in a replay too: it reports each IDL version Parsed Events activated inside the window. `--json` saves the coverage alongside the findings.

Replay starts with no state from before the window, so the first signer of each admin instruction becomes its baseline, and a proposal created before the window shows without its contents when it executes. Discovery uses on-chain state as it is today: current multisig members, authorities and vault balances. Vault drains can't be replayed once a vault is empty, which shows as `nothing to watch` for `treasury-outflow`.
