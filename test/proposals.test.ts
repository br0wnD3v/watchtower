import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { getAddressEncoder, address } from '@solana/kit';
import { describe, expect, it, vi } from 'vitest';
import { PROGRAMS } from '../src/constants.js';
import { detect } from '../src/detectors/index.js';
import { Engine } from '../src/engine.js';
import { parseUnits } from '../src/format.js';
import type { ParsedEventsClient } from '../src/helius/parsedEvents.js';
import { checkIdlChanges, idlChangesBetween } from '../src/idlWatch.js';
import { fromParsedEvents } from '../src/model.js';
import type { ParsedTransactionResult } from 'helius-sdk/parsedEvents/types';
import { context, KEYS, tx } from './helpers.js';

const REAL = {
    program: 'KLend2g3cP87fffoy8q1mQqGKjrxjC8boSyAYavgmjD',
    programData: '9uSbGW1y9H5Av6H5TKxQ1wnFApSq2t3oEpfF2YfjDQGA',
    buffer: 'J3oBkTkDXU3TcAggJEa3YeBZE5om5yNAdTtLVNXFD47',
    vault: 'GzFgdRJXmawPhGeBsyRCDLx4jAKPsvbUqoqitzppkzkW',
    spill: '5ggs2vd1csz74YMCzxesmcUEd3ycYFKAW6kfyttVYwBv',
    rent: 'SysvarRent111111111111111111111111111111111',
    clock: 'SysvarC1ock11111111111111111111111111111111',
};

/** Squads v4 `TransactionMessage` holding one upgradeable-loader `upgrade` of REAL.program. */
function upgradeMessage(): string {
    const keys = [
        REAL.vault,
        REAL.programData,
        REAL.program,
        REAL.buffer,
        REAL.spill,
        REAL.rent,
        REAL.clock,
        PROGRAMS.bpfLoaderUpgradeable,
    ];
    const encode = getAddressEncoder();
    const bytes = [1, 1, 4, keys.length, ...keys.flatMap((k) => [...encode.encode(address(k))])];
    const accountIndexes = [1, 2, 3, 4, 5, 6, 0];
    bytes.push(1, 7, accountIndexes.length, ...accountIndexes, 4, 0, 3, 0, 0, 0);
    bytes.push(0);
    return Buffer.from(bytes).toString('base64');
}

function realContext() {
    const ctx = context();
    const program = {
        id: REAL.program,
        label: 'Kamino Lend',
        programData: REAL.programData,
        privilegedInstructions: new Set<string>(),
        instructionsByDiscriminator: new Map<string, string>(),
        adminKeys: [],
    };
    ctx.targets.programs.set(REAL.program, program);
    ctx.targets.programsByProgramData.set(REAL.programData, program);
    return ctx;
}

describe('upgrade-proposal', () => {
    it('alerts when a v4 proposal contains an upgrade, then links the approval to it', () => {
        const ctx = realContext();
        const proposed = detect(
            tx('sig-propose', 100, [
                {
                    programId: PROGRAMS.squadsV4,
                    name: 'vaultTransactionCreate',
                    accounts: [
                        ['multisig', KEYS.multisig],
                        ['transaction', KEYS.configTx],
                        ['creator', KEYS.member, true],
                    ],
                    args: { args: { vaultIndex: 0, ephemeralSigners: 0, transactionMessage: upgradeMessage(), memo: null } },
                },
                {
                    programId: PROGRAMS.squadsV4,
                    name: 'proposalCreate',
                    accounts: [
                        ['multisig', KEYS.multisig],
                        ['proposal', KEYS.proposal],
                        ['creator', KEYS.member, true],
                    ],
                    args: { args: { transactionIndex: '7', draft: false } },
                },
            ]),
            ctx,
        ).filter((f) => f.detector === 'upgrade-proposal');
        expect(proposed).toHaveLength(1);
        expect(proposed[0]).toMatchObject({ severity: 'high', title: 'Program upgrade proposed', subject: KEYS.multisig });
        expect(proposed[0]!.description).toContain('deploy new bytecode to Kamino Lend');
        expect(proposed[0]!.description).toContain('1 day time lock');
        expect(proposed[0]!.details.Buffer).toBe(REAL.buffer);

        const approved = detect(
            tx('sig-approve', 110, [
                {
                    programId: PROGRAMS.squadsV4,
                    name: 'proposalApprove',
                    accounts: [
                        ['multisig', KEYS.multisig],
                        ['member', KEYS.attacker, true],
                        ['proposal', KEYS.proposal],
                    ],
                },
            ]),
            ctx,
        ).filter((f) => f.detector === 'upgrade-proposal');
        expect(approved[0]).toMatchObject({ severity: 'medium', title: 'Program upgrade approved by a member' });
        expect(approved[0]!.details['Proposed in']).toBe('sig-propose');
    });

    it('reads a v3 addInstruction that stages an upgrade', () => {
        const data = Buffer.from([3, 0, 0, 0]).toString('base64');
        const keys = [REAL.programData, REAL.program, REAL.buffer, REAL.spill, REAL.rent, REAL.clock, REAL.vault].map((pubkey) => ({
            pubkey,
        }));
        const [finding] = detect(
            tx('sig-v3', 100, [
                {
                    programId: PROGRAMS.squadsV3,
                    name: 'addInstruction',
                    accounts: [
                        ['multisig', KEYS.multisig],
                        ['transaction', KEYS.configTx],
                        ['creator', KEYS.member, true],
                    ],
                    args: { incomingInstruction: { programId: PROGRAMS.bpfLoaderUpgradeable, keys, data } },
                },
            ]),
            realContext(),
        );
        expect(finding).toMatchObject({ detector: 'upgrade-proposal', title: 'Program upgrade proposed' });
    });

    it('ignores proposals that do not touch a watched program', () => {
        const ctx = context();
        const findings = detect(
            tx('sig-other', 100, [
                {
                    programId: PROGRAMS.squadsV4,
                    name: 'vaultTransactionCreate',
                    accounts: [
                        ['multisig', KEYS.multisig],
                        ['transaction', KEYS.configTx],
                        ['creator', KEYS.member, true],
                    ],
                    args: { args: { transactionMessage: upgradeMessage() } },
                },
            ]),
            ctx,
        );
        expect(findings.filter((f) => f.detector === 'upgrade-proposal')).toEqual([]);
    });
});

describe('Squads v4 transaction buffers', () => {
    const SQUADS_BUFFER = 'Buffer11111111111111111111111111111111111111';
    const u32 = (n: number) => [n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff];
    const bytes = (hex: string, ...rest: number[][]) => Uint8Array.from([...Buffer.from(hex, 'hex'), ...rest.flat()]);

    /** `transactionBufferCreate`, `transactionBufferExtend` and `vaultTransactionCreateFromBuffer` as Parsed Streams sends them: undecoded. */
    function bufferCreate(message: Uint8Array, chunk: Uint8Array) {
        const hash = [...createHash('sha256').update(message).digest()];
        const data = bytes('f5c9716c253f1d59', [0, 0], hash, [message.length & 0xff, message.length >> 8], u32(chunk.length), [...chunk]);
        return {
            programId: PROGRAMS.squadsV4,
            name: null,
            raw: { data, accounts: [KEYS.multisig, SQUADS_BUFFER, KEYS.member, KEYS.member, PROGRAMS.system] },
        };
    }
    function bufferExtend(chunk: Uint8Array) {
        const data = bytes('e69d433805eef592', u32(chunk.length), [...chunk]);
        return { programId: PROGRAMS.squadsV4, name: null, raw: { data, accounts: [KEYS.multisig, SQUADS_BUFFER, KEYS.member] } };
    }
    function createFromBuffer() {
        const accounts = [KEYS.multisig, KEYS.configTx, KEYS.member, KEYS.member, PROGRAMS.system, SQUADS_BUFFER, KEYS.member];
        return {
            programId: PROGRAMS.squadsV4,
            name: null,
            raw: { data: bytes('de36954457f630e7', [0, 0], u32(6), [0, 0, 0, 0, 0, 0], [0]), accounts },
        };
    }
    const proposalCreate = {
        programId: PROGRAMS.squadsV4,
        name: 'proposalCreate',
        accounts: [
            ['multisig', KEYS.multisig],
            ['proposal', KEYS.proposal],
            ['creator', KEYS.member, true],
        ] as [string, string, boolean?][],
    };
    const message = Uint8Array.from(Buffer.from(upgradeMessage(), 'base64'));
    const [first, rest] = [message.subarray(0, 100), message.subarray(100)];

    it('reassembles an upgrade proposed through a buffer, then links the approval to it', () => {
        const ctx = realContext();
        detect(tx('sig-buffer-create', 98, [bufferCreate(message, first)]), ctx);
        detect(tx('sig-buffer-extend', 99, [bufferExtend(rest)]), ctx);
        const proposed = detect(tx('sig-propose', 100, [createFromBuffer(), proposalCreate]), ctx).filter(
            (f) => f.detector === 'upgrade-proposal',
        );
        expect(proposed).toHaveLength(1);
        expect(proposed[0]).toMatchObject({ severity: 'high', title: 'Program upgrade proposed', subject: KEYS.multisig });
        expect(proposed[0]!.details).toMatchObject({ Proposer: KEYS.member, Buffer: REAL.buffer, 'Proposal transaction': KEYS.configTx });

        const approved = detect(
            tx('sig-approve', 110, [
                {
                    programId: PROGRAMS.squadsV4,
                    name: 'proposalApprove',
                    accounts: [
                        ['multisig', KEYS.multisig],
                        ['member', KEYS.attacker, true],
                        ['proposal', KEYS.proposal],
                    ],
                },
            ]),
            ctx,
        ).filter((f) => f.detector === 'upgrade-proposal');
        expect(approved[0]).toMatchObject({ title: 'Program upgrade approved by a member' });
    });

    it('ignores a buffer chunk seen twice, as when backfill and the stream both deliver it', () => {
        const ctx = realContext();
        detect(tx('sig-buffer-create', 98, [bufferCreate(message, first)]), ctx);
        detect(tx('sig-buffer-extend', 99, [bufferExtend(rest)]), ctx);
        detect(tx('sig-buffer-extend', 99, [bufferExtend(rest)]), ctx);
        const proposed = detect(tx('sig-propose', 100, [createFromBuffer(), proposalCreate]), ctx);
        expect(proposed.map((f) => f.title)).toContain('Program upgrade proposed');
    });

    it('reports a proposal whose buffer was not seen in full as undecoded, without guessing', () => {
        const ctx = realContext();
        detect(tx('sig-buffer-create', 98, [bufferCreate(message, first)]), ctx);
        const findings = detect(tx('sig-propose', 100, [createFromBuffer(), proposalCreate]), ctx);
        expect(findings.filter((f) => f.detector === 'upgrade-proposal')).toEqual([]);
        expect(findings.find((f) => f.detector === 'multisig-proposal')!.details['Would do']).toBe('contents could not be decoded');
    });

    it('decodes a real mainnet proposal written across two buffer transactions', () => {
        /** A Squads v4 proposal of 5 calls: `transactionBufferCreate`, `transactionBufferExtend`, then `vaultTransactionCreateFromBuffer`. */
        const fixture = JSON.parse(
            readFileSync(new URL('./fixtures/squads-v4-buffer.json', import.meta.url), 'utf8'),
        ) as ParsedTransactionResult[];
        const multisig = '2ZDFsDzcztw6fRgpvRECytSDTnWtJbUDiVqck7CJS1oi';
        const ctx = context();
        ctx.targets.multisigs.set(multisig, { address: multisig, label: 'Ops multisig', version: 4, threshold: 1, timeLockSeconds: 0 });
        const findings = fixture.flatMap((result) => detect(fromParsedEvents(result)!, ctx));
        const created = findings.find((f) => f.detector === 'multisig-proposal')!;
        expect(created.details['Would do']).toMatch(/^call program \S+ ×5$/);
        expect(created.details['Proposal transaction']).toBe('AFnixFgNEu8uRjq2mcMz4EaHYrEkAGPWwKTMh6DPhhsc');
    });
});

describe('treasury-outflow', () => {
    const sol = (lamports: number, to = KEYS.attacker) => ({ fromUserAccount: KEYS.treasury, toUserAccount: to, amount: lamports });

    it('alerts on one large net outflow, ignoring self-transfers', () => {
        const ctx = context({ thresholds: { SOL: 100 } });
        const findings = detect(
            tx('sig-drain', 100, [], {
                nativeTransfers: [
                    sol(150_000_000_000),
                    { fromUserAccount: KEYS.attacker, toUserAccount: KEYS.treasury, amount: 20_000_000_000 },
                    sol(5_000_000_000, KEYS.treasury),
                ],
            }),
            ctx,
        ).filter((f) => f.detector === 'treasury-outflow');
        expect(findings).toHaveLength(1);
        expect(findings[0]).toMatchObject({ severity: 'high', title: 'Large treasury outflow', subject: KEYS.treasury, stages: ['drain'] });
        expect(findings[0]!.details.Amount).toBe('130 SOL');
    });

    it('nets funds routed through the treasury in one transaction', () => {
        const ctx = context({ thresholds: { SOL: 100 } });
        const routed = detect(
            tx('sig-route', 100, [], {
                nativeTransfers: [
                    { fromUserAccount: KEYS.attacker, toUserAccount: KEYS.treasury, amount: 500_000_000_000 },
                    sol(500_000_000_000),
                ],
            }),
            ctx,
        );
        expect(routed).toEqual([]);
    });

    it('raises one critical alert when small outflows add up within the window', () => {
        const ctx = context({ thresholds: { SOL: 100 } });
        const titles = [1, 2, 3, 4, 5].flatMap((i) =>
            detect(tx(`sig-${i}`, 100 + i, [], { nativeTransfers: [sol(80_000_000_000)] }), ctx).map((f) => f.title),
        );
        expect(titles).toEqual(['Sustained treasury outflow']);
    });

    it('converts token thresholds with the transfer decimals', () => {
        const usdc = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
        const ctx = context({ thresholds: { [usdc]: 50_000 } });
        const [finding] = detect(
            tx('sig-usdc', 100, [], {
                tokenTransfers: [
                    {
                        fromUserAccount: KEYS.treasury,
                        toUserAccount: KEYS.attacker,
                        fromTokenAccount: 'a',
                        toTokenAccount: 'b',
                        // The API sends amounts beyond 2^53 as strings, though the SDK types them as numbers.
                        rawTokenAmount: '60000000000' as unknown as number,
                        decimals: 6,
                        tokenStandard: 'Fungible',
                        mint: usdc,
                    },
                ],
            }),
            ctx,
        );
        expect(finding?.details.Amount).toBe('60,000 EPjF…Dt1v');
    });

    it('parses UI amounts into raw units', () => {
        expect(parseUnits(1.5, 6)).toBe(1_500_000n);
        expect(parseUnits(100, 9)).toBe(100_000_000_000n);
    });
});

describe('nonce-authority', () => {
    const initNonce = (authority: string) => ({
        programId: PROGRAMS.system,
        name: 'initialize_nonce_account',
        accounts: [
            ['nonce_account', KEYS.nonce],
            ['recent_blockhashes_sysvar', KEYS.buffer],
        ] as [string, string][],
        args: { nonce_authority: authority },
    });

    it('flags a nonce account someone else created for a multisig member', () => {
        const [finding] = detect(tx('sig-nonce', 100, [initNonce(KEYS.member)], { feePayer: KEYS.attacker }), context());
        expect(finding).toMatchObject({ severity: 'high', title: 'Nonce account created for a privileged key', subject: KEYS.multisig });
        expect(finding!.details['Created by']).toBe(KEYS.attacker);
    });

    it('rates a nonce account the key set up for itself lower', () => {
        const [finding] = detect(tx('sig-self', 100, [initNonce(KEYS.member)], { feePayer: KEYS.member }), context());
        expect(finding?.severity).toBe('medium');
    });

    it('ignores nonce accounts for unrelated keys', () => {
        expect(detect(tx('sig-unrelated', 100, [initNonce(KEYS.attacker)]), context())).toEqual([]);
    });

    it('flags a nonce authority reassigned to a privileged key', () => {
        const [finding] = detect(
            tx(
                'sig-authorize',
                100,
                [
                    {
                        programId: PROGRAMS.system,
                        name: 'authorize_nonce_account',
                        accounts: [
                            ['nonce_account', KEYS.nonce],
                            ['nonce_authority', KEYS.attacker, true],
                        ],
                        args: { new_nonce_authority: KEYS.member },
                    },
                ],
                { feePayer: KEYS.attacker },
            ),
            context(),
        );
        expect(finding?.title).toBe('Nonce authority moved to a privileged key');
    });
});

describe('failed admin attempts', () => {
    const adminCall = (signature: string, signer: string, failed: boolean) =>
        tx(signature, 100, [{ programId: KEYS.program, name: 'set_admin', accounts: [['admin', signer, true]] }], { failed });

    it('rates a failed call from an unknown signer high and from a known signer low', () => {
        const ctx = context({ privileged: ['set_admin'] });
        detect(adminCall('sig-ok', KEYS.member, false), ctx);
        expect(detect(adminCall('sig-probe', KEYS.attacker, true), ctx)[0]).toMatchObject({
            severity: 'high',
            title: 'Unauthorized attempt on set_admin',
        });
        expect(detect(adminCall('sig-typo', KEYS.member, true), ctx)[0]).toMatchObject({ severity: 'low' });
    });

    it('does not let a failed call extend the signer baseline', () => {
        const ctx = context({ privileged: ['set_admin'] });
        detect(adminCall('sig-ok', KEYS.member, false), ctx);
        detect(adminCall('sig-probe', KEYS.attacker, true), ctx);
        expect(detect(adminCall('sig-later', KEYS.attacker, false), ctx)[0]?.title).toBe('New signer on set_admin');
    });

    it('runs only failure-aware detectors on failed transactions', () => {
        const upgrade = tx(
            'sig-failed-upgrade',
            100,
            [{ programId: PROGRAMS.bpfLoaderUpgradeable, name: 'upgrade', accounts: [['program_account', KEYS.program]] }],
            { failed: true },
        );
        expect(detect(upgrade, context())).toEqual([]);
    });
});

describe('idl-change', () => {
    function fakeIdlEvents(versions: { slot: number; sources: string[] }[], idls: Record<number, unknown>): ParsedEventsClient {
        return {
            listIdlVersions: vi.fn(async () => versions),
            getIdl: vi.fn(async (_program: string, slot: number) => idls[slot]),
        } as unknown as ParsedEventsClient;
    }

    it('records a baseline first, then flags a new admin-looking instruction', async () => {
        const ctx = context();
        const engine = new Engine(ctx, []);
        const v1 = { instructions: [{ name: 'deposit', accounts: [] }] };
        const v2 = {
            instructions: [
                { name: 'deposit', accounts: [] },
                { name: 'set_admin', accounts: [] },
            ],
        };

        expect(
            await checkIdlChanges(fakeIdlEvents([{ slot: 10, sources: ['anchor'] }], { 10: v1 }), engine, ctx.state, ctx.targets, 'queue'),
        ).toBe(0);

        const versions = [
            { slot: 10, sources: ['anchor'] },
            { slot: 20, sources: ['anchor'] },
        ];
        expect(await checkIdlChanges(fakeIdlEvents(versions, { 10: v1, 20: v2 }), engine, ctx.state, ctx.targets, 'queue')).toBe(1);
        const [finding] = ctx.state.pendingAlerts();
        expect(finding).toMatchObject({ severity: 'high', title: 'New admin instruction in IDL', signature: null });
        expect(finding!.description).toContain('added set_admin');
    });

    it('replays each IDL version published inside a window against the one before it', async () => {
        const ctx = context();
        const v1 = { instructions: [{ name: 'deposit', accounts: [] }] };
        const v2 = { instructions: [...v1.instructions, { name: 'set_admin', accounts: [] }] };
        const v3 = { instructions: [{ name: 'set_admin', accounts: [] }] };
        const versions = [10, 20, 30, 40].map((slot) => ({ slot, sources: ['anchor'] }));
        const events = fakeIdlEvents(versions, { 10: v1, 20: v2, 30: v3, 40: v3 });

        const findings = await idlChangesBetween(events, ctx.targets, 10, 30);
        expect(findings.map((f) => [f.slot, f.title])).toEqual([
            [20, 'New admin instruction in IDL'],
            [30, 'IDL updated'],
        ]);
        expect(findings[1]!.description).toContain('removed deposit');
    });
});

describe('treasury-outflow sustained rule', () => {
    it('does not call a single huge outflow sustained', () => {
        const ctx = context({ thresholds: { SOL: 100 } });
        const titles = detect(
            tx('sig-huge', 100, [], {
                nativeTransfers: [{ fromUserAccount: KEYS.treasury, toUserAccount: KEYS.attacker, amount: 1_000_000_000_000 }],
            }),
            ctx,
        ).map((f) => f.title);
        expect(titles).toEqual(['Large treasury outflow']);
    });
});

describe('nonce-authority on parser-v2 byte-split pubkeys', () => {
    it('reassembles a nonce authority that the System decoder split into byte fields', () => {
        const bytes = [...getAddressEncoder().encode(address(KEYS.member))];
        const split: Record<string, string> = { nonce_authority: String(bytes[0]) };
        bytes.slice(1).forEach((b, i) => (split[`field_${i + 2}`] = String(b)));
        const [finding] = detect(
            tx(
                'sig-split',
                100,
                [{ programId: PROGRAMS.system, name: 'initialize_nonce_account', accounts: [['nonce_account', KEYS.nonce]], args: split }],
                {
                    feePayer: KEYS.attacker,
                },
            ),
            context(),
        );
        expect(finding).toMatchObject({ detector: 'nonce-authority', severity: 'high' });
        expect(finding!.details.Authority).toBe(KEYS.member);
    });
});
