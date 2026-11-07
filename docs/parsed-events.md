# How Watchtower uses Parsed Events and Parsed Streams

Watchtower is a working example of building on Helius Parsed Events (history) and Parsed Streams (live). This guide maps each thing Watchtower does to the API call behind it, with links to the code, so you can reuse the patterns in your own app.

Every call goes through the [Helius TypeScript SDK](https://github.com/helius-labs/helius-sdk): `helius.parsedEvents.scan`, `helius.parsedEvents.getTransactionHistory`, and `parsedTransactionSubscribe` from `helius-sdk/websockets/parsedStreams`. The thin adapters are in [`src/helius/`](../src/helius).

## Why these APIs fit security monitoring

Security signals live in **which instruction ran, with which arguments, signed by whom**. Both APIs return transactions with every instruction decoded, inner (CPI) instructions included:

- **Names:** the instruction name, such as `update_admin` or `set_authority`, from the program's IDL, or from Helius's native decoders for System, SPL Token, Token-2022, Stake and the upgradeable loader.
- **Arguments:** decoded named args, such as a new withdrawal limit or the bytes of a proposed transaction.
- **Accounts:** each account with its IDL role (`admin`, `multisig`, `program_data_account`) and its signer and writable flags.

So detectors compare names and roles instead of parsing bytes, and the same detector works on any Anchor program whose IDL Parsed Events has.

**One shape for history and live.** [`src/model.ts`](../src/model.ts) converts both APIs into one `ParsedTx` (`fromParsedEvents` and `fromStream`). Every detector reads only that, so a transaction found by a history scan and the same transaction arriving on the stream produce the same finding, and are deduplicated by its id.

## Parsed Events scan: search an address's history on the server

`scan` searches one address's history and returns only the transactions that match a filter, already parsed. Watchtower never downloads a busy program's full history to find the few transactions that matter. ([`ParsedEventsClient.scanAll`](../src/helius/parsedEvents.ts))

### The scan plans

Each watched address gets a scan plan with its own filter ([`scanPlans` in `src/targets.ts`](../src/targets.ts)):

| What Watchtower watches | Address scanned           | `match` filter                                                                      | Finds                                                       |
| ----------------------- | ------------------------- | ----------------------------------------------------------------------------------- | ----------------------------------------------------------- |
| Deployments             | The program's ProgramData | Upgradeable loader, `scope: address`                                                | Upgrades, authority changes, closes                         |
| Admin calls by a key    | Each admin key            | The program, `scope: transaction`                                                   | Every call that key made to the program                     |
| Admin calls by anyone   | The program               | The program plus the admin-only instruction names, `scope: transaction`             | Admin calls from any signer, including an unknown new admin |
| Multisigs               | Each Squads multisig      | Squads v3 and v4, `scope: address`                                                  | Proposals, votes, executions, config changes                |
| Mints                   | Each mint                 | SPL Token and Token-2022 by **discriminator** (`0x06`, `0x07`, …), `scope: address` | Authority changes, mints, freezes, extension updates        |
| Treasuries              | Each treasury             | Watched mints, or System and both token programs                                    | Outflows                                                    |
| Custody keys            | Each watched key          | Stake, System and token instructions by discriminator                               | Stake, token-account and delegate authority handoffs        |

Two patterns are worth copying:

- **Scan the small address, not the busy program.** An admin key's history is a few hundred transactions; a perps program can run millions a day. Scanning the key with the program as the filter finds the same admin calls for a fraction of the credits. The program-wide plan is the backstop for admin calls from keys Watchtower doesn't know yet.
- **Filter by discriminator when there's no instruction name to use.** The mint plans match SPL Token and Token-2022 by instruction discriminator, so only authority changes, mints and extension updates come back, not every transfer.

### Pagination, budgets and credits

A scan returns up to the `limit` of matches and scans at most 10,000 transactions per request. `scanAll` follows `paginationToken` until the window ends or a total budget (`backfill.maxScannedTransactions`) is spent. A scan costs 10 credits plus 1 per 1,000 transactions scanned; the response reports `scannedTransactions`, `matchedTransactions`, `creditsCharged` and `scannedThrough`, which Watchtower shows in the dashboard's coverage table.

### Cursors: catch up without gaps

[`src/backfill.ts`](../src/backfill.ts) keeps one cursor per scan plan:

- **First scan:** reads the lookback window **newest-first** (`sortOrder: desc`), so a budget-limited scan covers the most recent history, then processes the results oldest-first so proposals come before their approvals.
- **Later scans:** read **oldest-first** from the cursor up to the current slot (`slot: { gt: cursor, lte: untilSlot }`), with `minContextSlot` so a lagging node can't return a shorter history. When the budget runs out mid-slot, the next run resumes at the start of that slot.

### Short scans for discovery

Discovery uses small, budgeted scans to work out what to watch ([`src/discover/index.ts`](../src/discover/index.ts)):

- **`findGoverningMultisig`:** finds the Squads multisig behind a vault from the vault's own history.
- **`discoverAdmins`:** finds who signs a program's admin calls, from its recent admin-instruction history.
- **`discoverVaults`:** finds the program-derived addresses that pay out tokens in recent transactions.
- **`nonceAccountsOf`:** finds durable nonce accounts a privileged key created or controls.
- **`recentAccountsByName`:** samples recent transactions for accounts passed under a given IDL name, to find config accounts on programs too large to list.

### Replay

[`replay`](../src/commands/replay.ts) runs the same scans over any past window and feeds the results through every detector, which is how Watchtower checks it would have caught a real exploit ([docs/cli.md, step 10](cli.md#10-replay-an-exploit)).

## Parsed Events transaction history: how old is this wallet?

`getTransactionHistory` with `sortOrder: asc, limit: 1` returns an address's first transaction. Watchtower uses it to flag an admin call from a wallet that first appeared on-chain days earlier, and a listing of a token created weeks earlier ([`src/vet.ts`](../src/vet.ts)). In the Drift exploit, the admin wallet was one day old and the listed token three weeks old.

## Parsed Events IDL endpoints: what a program can do, and when it changed

[`GET /v1/parsed-events/idl/{programId}`](https://www.helius.dev/docs/api-reference/parsed-events/idl-versions) lists the IDL versions Parsed Events has used for a program, each with the slot it took effect; [`/{programId}/{slot}`](https://www.helius.dev/docs/api-reference/parsed-events/idl) returns the IDL in force at that slot. The SDK doesn't wrap these yet, so [`ParsedEventsClient`](../src/helius/parsedEvents.ts) calls them directly.

- **Finding admin instructions:** names and signer roles in the IDL pre-select likely admin-only instructions in Setup ([`src/discover/idl.ts`](../src/discover/idl.ts)).
- **Reading config accounts:** the IDL's account layouts let Watchtower decode admin fields like `GlobalConfig.admin` and diff settings over time.
- **Spotting new IDLs:** the `idl-change` detector polls for new versions and flags newly added admin-looking instructions ([`src/idlWatch.ts`](../src/idlWatch.ts)).
- **Replaying the past correctly:** `replay` loads the IDL that was live when the window started, not today's, and reports each version activated inside the window. A window given as dates is converted to slots from block times, since slot duration drifts over months.

## Parsed Streams: the same decoded transactions, live

`parsedTransactionSubscribe` pushes decoded transactions over a WebSocket as they confirm. Watchtower opens one connection per monitor with one subscription per kind of target ([`subscriptions` in `src/targets.ts`](../src/targets.ts), [`ParsedStreamsClient`](../src/helius/parsedStreams.ts)):

| Subscription  | Filter                                                                                      |
| ------------- | ------------------------------------------------------------------------------------------- |
| `deployments` | Upgradeable loader, accounts include the programs and their ProgramData                     |
| `admin`       | The program, its admin-only `instructionNames`, failed transactions included                |
| `multisigs`   | Squads v3 and v4, accounts include the multisigs                                            |
| `mints`       | SPL Token and Token-2022, authority and mint `instructionNames`, accounts include the mints |
| `treasuries`  | Accounts include the treasuries                                                             |
| `custody`     | Stake, System and token authority `instructionNames`, accounts include the watched keys     |
| `nonces`      | System `initialize_nonce_account` and `authorize_nonce_account`, chain-wide                 |

Every subscription uses `commitment: confirmed`, `details: full` and `includeCpi: true`, so an admin call made through a multisig or another program still matches. The `admin` subscription also includes failed transactions, since a failed admin call from an unknown signer often means someone is probing access control.

**Streams don't replay, so scans fill the gaps.** When the connection drops and comes back, Watchtower runs the cursor scans from where each plan stopped, so nothing that confirmed while disconnected is missed. Cursors only advance from the stream once that plan's catch-up reached the present ([`src/monitor.ts`](../src/monitor.ts)). A rejected subscription is skipped and reported, and holds its cursors back so the next catch-up covers it.

## When an instruction isn't in the IDL

If the program's IDL doesn't include an instruction, both APIs still send it, undecoded, with `rawData` (base58) and `rawAccounts`. Squads v4's on-chain IDL predates its transaction-buffer instructions, so Watchtower decodes those itself from the raw bytes and the Anchor discriminators ([`decodeTransactionBuffers` in `src/discover/squads.ts`](../src/discover/squads.ts)). Scans can still target such instructions by discriminator even though there's no name to filter on.

## Limits to design around

| API                  | Limit                                                                                                                                          |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| Parsed Events `scan` | 20 programs per `match`; 50 instruction names and 50 discriminators per program; 10,000 transactions scanned per request                       |
| Parsed Streams       | 10 programs, 50 instruction names, 100 included accounts and 20 roles per filter; 25 subscriptions per connection; `confirmed` only; no replay |

Watchtower splits long lists into several plans or subscriptions to stay within these, and refuses a config that would need more than 25 subscriptions on one connection.
