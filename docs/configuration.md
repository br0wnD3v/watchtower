# Configuration and credits

See [`watchtower.example.yaml`](../watchtower.example.yaml) for every option. Any string can reference `${ENV_VAR}`, and `.env` is loaded automatically. Configs saved from the dashboard may only keep the references already in alert channel secrets, so the browser cannot read other variables.

| Variable                    | Default                                                                                                |
| --------------------------- | ------------------------------------------------------------------------------------------------------ |
| `HELIUS_API_KEY`            | required                                                                                               |
| `HELIUS_RPC_URL`            | the Helius SDK's (`https://mainnet.helius-rpc.com`)                                                    |
| `HELIUS_PARSED_STREAMS_URL` | the Helius SDK's (`wss://beta.helius-rpc.com`)                                                         |
| `WATCHTOWER_PASSWORD`       | none; required to [host](dashboard.md#host-your-own-dashboard) on a public interface, unless read-only |
| `WATCHTOWER_READONLY`       | `false`                                                                                                |
| `WATCHTOWER_VERIFY_URL`     | `https://verify.osec.io`                                                                               |

Parsed Events uses the SDK's endpoint, `https://mainnet.helius-rpc.com/v1/parsed-events`. Requests carry an `X-Helius-Client: helius-watchtower/<version>` header.

## Credits

A Parsed Events scan costs 10 credits plus 1 for each 1,000 transactions scanned. Matched transactions returned in full also cost credits: in testing, a busy exchange wallet with 14,156 matches cost about 1,560 credits.

- **Which addresses are scanned:** the program's ProgramData, each admin key, each multisig, each mint, each treasury, and the program itself when admin instructions are configured. `report` also scans each privileged key's history for nonce accounts.
- **How long the histories are:** ProgramData and multisig histories are short and cost about 11 credits a run. Busy programs, mints and treasuries are long.
- **Capping a run:** `backfill.maxScannedTransactions` caps each scan, and the report lists the credits each one used.
- **First scans:** a first scan reads newest-first, so it covers the most recent history within the cap and then starts monitoring from the present.
- **Very busy programs:** admin-instruction gap-fills on programs like Jupiter scan the program's whole transaction stream. A long downtime can exceed the cap, and the scan continues on the next run. The live stream is unaffected.
- **Several monitors:** each runs its own stream connection and scans, so credits add up per monitor.
