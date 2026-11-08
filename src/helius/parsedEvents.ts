import { CLIENT_ID } from '../constants.js';
import type { HeliusClient } from 'helius-sdk';
import type {
    GetParsedTransactionHistoryRequest,
    GetParsedTransactionHistoryResponse,
    ParsedTransactionResult,
    ScanParsedTransactionHistoryRequest,
    ScanTransactionsResponse,
} from 'helius-sdk/parsedEvents/types';

export type ScanRequest = ScanParsedTransactionHistoryRequest<'transactions'>;

export interface ScanProgress {
    /** True once the server has no more history in the requested window. */
    windowEnded: boolean;
    scannedTransactions: number;
    matchedTransactions: number;
    creditsCharged: number;
    scannedThrough?: { slot: number; blockTime: number | null };
}

/** Parsed Events IDL endpoints (https://www.helius.dev/docs/api-reference/parsed-events/idl), which the Helius SDK does not cover. */
const IDL_BASE_URL = 'https://mainnet.helius-rpc.com/v1/parsed-events/idl';
const MAX_SCAN_BUDGET_PER_REQUEST = 10_000;
const REQUEST_TIMEOUT_MS = 60_000;
const MAX_ATTEMPTS = 5;
/** SDK errors read `Helius HTTP <status>: <message>`; also retries an archive that is behind a `minContextSlot`. */
const RETRYABLE = /Helius HTTP (429|5\d\d)|Minimum context slot/;
const NO_IDL = /Helius HTTP 404: .*no IDLs found/;

export class ParsedEventsClient {
    readonly #helius: HeliusClient;
    readonly #apiKey: string;

    constructor(helius: HeliusClient, apiKey: string) {
        this.#helius = helius;
        this.#apiKey = apiKey;
    }

    scan(request: ScanRequest): Promise<ScanTransactionsResponse> {
        return retry('scan', () => this.#helius.parsedEvents.scan({ commitment: 'confirmed', ...request }));
    }

    transactionHistory(request: GetParsedTransactionHistoryRequest): Promise<GetParsedTransactionHistoryResponse> {
        return retry('transaction-history', () => this.#helius.parsedEvents.getTransactionHistory({ commitment: 'confirmed', ...request }));
    }

    /** Ascending by activation slot; empty for a program Parsed Events has no IDL for, which it answers with a 404. */
    async listIdlVersions(programId: string): Promise<{ slot: number; sources: string[] }[]> {
        try {
            return await retry('idl', () => this.#getIdlEndpoint(programId));
        } catch (error) {
            if (NO_IDL.test((error as Error).message)) return [];
            throw error;
        }
    }

    getIdl(programId: string, activationSlot: number): Promise<unknown> {
        return retry('idl', () => this.#getIdlEndpoint(`${programId}/${activationSlot}`));
    }

    /** Follows `paginationToken` until the window ends or `maxScannedTransactions` is spent. */
    async *scanAll(
        request: Omit<ScanRequest, 'paginationToken' | 'budget'>,
        maxScannedTransactions: number,
        onProgress?: (progress: ScanProgress) => void,
    ): AsyncGenerator<ParsedTransactionResult> {
        const progress: ScanProgress = { windowEnded: false, scannedTransactions: 0, matchedTransactions: 0, creditsCharged: 0 };
        let paginationToken: string | null | undefined;
        do {
            const remaining = maxScannedTransactions - progress.scannedTransactions;
            if (remaining <= 0) return;
            const page = await this.scan({
                ...request,
                paginationToken,
                budget: { maxScannedTransactions: Math.min(remaining, MAX_SCAN_BUDGET_PER_REQUEST) },
            });
            paginationToken = page.paginationToken;
            progress.windowEnded = !paginationToken;
            progress.scannedTransactions += page.scan.scannedTransactions;
            progress.matchedTransactions += page.scan.matchedTransactions;
            progress.creditsCharged += page.scan.creditsCharged;
            progress.scannedThrough = page.scan.scannedThrough ?? progress.scannedThrough;
            onProgress?.(progress);
            yield* page.data;
        } while (paginationToken);
    }

    async #getIdlEndpoint<T>(path: string): Promise<T> {
        const response = await fetch(`${IDL_BASE_URL}/${path}?api-key=${encodeURIComponent(this.#apiKey)}`, {
            headers: { 'X-Helius-Client': CLIENT_ID },
            signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
        });
        if (!response.ok) throw new Error(`Helius HTTP ${response.status}: ${(await response.text()).slice(0, 300)}`);
        return (await response.json()) as T;
    }
}

async function retry<T>(endpoint: string, request: () => Promise<T>): Promise<T> {
    for (let attempt = 1; ; attempt++) {
        try {
            return await withTimeout(request(), REQUEST_TIMEOUT_MS, endpoint);
        } catch (error) {
            const message = (error as Error).message;
            if (attempt >= MAX_ATTEMPTS || !RETRYABLE.test(message)) throw new Error(`Parsed Events ${endpoint} failed: ${message}`);
            await sleep(500 * 2 ** attempt);
        }
    }
}

/** The SDK's REST calls take no abort signal, so a hung request is abandoned, not cancelled. */
function withTimeout<T>(promise: Promise<T>, ms: number, endpoint: string): Promise<T> {
    let timer: NodeJS.Timeout | undefined;
    const timeout = new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error(`Helius HTTP 504: ${endpoint} timed out after ${ms / 1000}s`)), ms);
    });
    return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

function sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
}
