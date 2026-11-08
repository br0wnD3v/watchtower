import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { parseEnv } from 'node:util';
import { parse as parseYaml } from 'yaml';
import { z } from 'zod';

export const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'] as const;
export type Severity = (typeof SEVERITIES)[number];

export function severityRank(severity: Severity): number {
    return SEVERITIES.indexOf(severity);
}

const pubkey = z.string().regex(/^[1-9A-HJ-NP-Za-km-z]{32,44}$/, 'expected a base58 public key');
const severity = z.enum(SEVERITIES);

const sinkSchema = z.discriminatedUnion('type', [
    z.object({ type: z.literal('console'), minSeverity: severity.optional() }),
    z.object({ type: z.literal('discord'), url: z.url(), minSeverity: severity.optional() }),
    z.object({ type: z.literal('slack'), url: z.url(), minSeverity: severity.optional() }),
    z.object({
        type: z.literal('telegram'),
        botToken: z.string().min(1),
        chatId: z.union([z.string(), z.number()]).transform(String),
        minSeverity: severity.optional(),
    }),
    z.object({
        type: z.literal('webhook'),
        url: z.url(),
        headers: z.record(z.string(), z.string()).default({}),
        minSeverity: severity.optional(),
    }),
]);

const configSchema = z.object({
    /** Shown on the monitor's dashboard tab. */
    name: z.string().optional(),
    programs: z
        .array(
            z.object({
                id: pubkey,
                name: z.string().optional(),
                /** Matched case- and separator-insensitively. */
                privilegedInstructions: z.array(z.string()).default([]),
                /** Admin keys to watch in addition to discovered ones, for programs whose IDL doesn't reveal them. */
                adminKeys: z.array(pubkey).default([]),
                /** Discover the program's vaults from its token payouts and alert on fast drains. */
                watchVaults: z.boolean().default(false),
            }),
        )
        .min(1, 'add at least one program'),
    multisigs: z.array(z.object({ address: pubkey, label: z.string().optional() })).default([]),
    mints: z.array(z.object({ address: pubkey, label: z.string().optional() })).default([]),
    treasuries: z
        .array(
            z.object({
                address: pubkey,
                label: z.string().optional(),
                /** Per-transaction outflow thresholds in UI units, keyed by mint address or `SOL`. */
                thresholds: z.record(z.union([pubkey, z.literal('SOL')]), z.number().positive()).default({}),
                alertOnAnyOutflow: z.boolean().default(false),
                windowMinutes: z.number().int().positive().default(60),
                /** When set, an outflow to any other address alerts. */
                allowedDestinations: z.array(pubkey).default([]),
            }),
        )
        .default([]),
    /** Keys checked for nonce-account setup, in addition to discovered authorities and multisig members. */
    watchedKeys: z.array(z.object({ address: pubkey, label: z.string().optional() })).default([]),
    idlPollMinutes: z.number().int().positive().default(10),
    /** Config account poll interval; admin calls also trigger a read. */
    configPollSeconds: z.number().int().positive().default(60),
    alerts: z
        .object({
            minSeverity: severity.default('low'),
            sinks: z.array(sinkSchema).default([{ type: 'console' }]),
            /** Repeats of a non-critical alert within this long of the first are sent as one summary; 0 sends each. */
            groupWindowSeconds: z.number().int().nonnegative().default(600),
        })
        .prefault({}),
    backfill: z
        .object({
            lookbackDays: z.number().int().positive().default(90),
            /** Per watched address, per run. */
            maxScannedTransactions: z.number().int().positive().default(50_000),
        })
        .prefault({}),
    stateFile: z.string().default('.watchtower/state.json'),
});

export type SinkConfig = z.infer<typeof sinkSchema>;
export type FileConfig = z.infer<typeof configSchema>;

export interface Config extends FileConfig {
    apiKey: string;
    endpoints: { rpc?: string; parsedStreams?: string };
    configPath: string;
}

export const DEFAULT_CONFIG_PATH = 'watchtower.yaml';

/** Variables set in the shell before startup; `.env` never overrides them. */
const SHELL_ENV = new Set(Object.keys(process.env));

/** Loads `.env` into `process.env`; on a later call, edited values replace earlier `.env` values. */
export function loadEnvFile(path = '.env'): void {
    if (!existsSync(path)) return;
    for (const [key, value] of Object.entries(parseEnv(readFileSync(path, 'utf8')))) {
        if (!SHELL_ENV.has(key)) process.env[key] = value;
    }
}

export function loadConfig(path = DEFAULT_CONFIG_PATH): Config {
    loadEnvFile();
    const configPath = resolve(path);
    if (!existsSync(configPath)) {
        throw new Error(`No config at ${configPath}. Run \`watchtower init\` first.`);
    }
    return { ...parseConfig(readRawConfig(configPath), path), apiKey: requireApiKey(), endpoints: endpointsFromEnv(), configPath };
}

/** The YAML document as written, with `${VAR}` references left in place. */
export function readRawConfig(path: string): unknown {
    return parseYaml(readFileSync(path, 'utf8'));
}

/** Validates a raw config after resolving `${VAR}` references. */
export function parseConfig(raw: unknown, source = 'config'): FileConfig {
    const result = configSchema.safeParse(interpolateEnv(raw));
    if (!result.success) throw new Error(`Invalid ${source}:\n${z.prettifyError(result.error)}`);
    return result.data;
}

export const MISSING_API_KEY = 'HELIUS_API_KEY is not set. Copy .env.example to .env and add your key from dashboard.helius.dev.';

export function requireApiKey(): string {
    const apiKey = process.env.HELIUS_API_KEY;
    if (!apiKey) throw new Error(MISSING_API_KEY);
    return apiKey;
}

export function endpointsFromEnv(): Config['endpoints'] {
    const { HELIUS_RPC_URL: rpc, HELIUS_PARSED_STREAMS_URL: parsedStreams } = process.env;
    return { ...(rpc ? { rpc } : {}), ...(parsedStreams ? { parsedStreams } : {}) };
}

/** Replaces `${VAR}` in string values; throws if a variable is unset. */
function interpolateEnv(value: unknown): unknown {
    if (typeof value === 'string') {
        return value.replace(/\$\{([A-Z0-9_]+)\}/g, (_, name: string) => {
            const resolved = process.env[name];
            if (resolved === undefined) throw new Error(`Config references \${${name}}, which is not set`);
            return resolved;
        });
    }
    if (Array.isArray(value)) return value.map(interpolateEnv);
    if (value && typeof value === 'object') {
        return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, interpolateEnv(v)]));
    }
    return value;
}
