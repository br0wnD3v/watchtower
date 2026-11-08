import { describe, expect, it } from 'vitest';
import { PROGRAMS } from '../src/constants.js';
import { adminKeyBehavior } from '../src/detectors/adminKeyBehavior.js';
import type { DetectorContext } from '../src/detectors/types.js';
import { context, KEYS, tx, type IxSpec, type TxOptions } from './helpers.js';

const ADMIN = 'Admin11111111111111111111111111111111111111';
const MARGINFI = 'MFv2hWf31Z9kbCa1snEPYctwafyhdvnV7FZnsebVacA';
/** Above the detector's minimum, so departures are reported. */
const BASELINE = 12;

function setup(): DetectorContext {
    const ctx = context();
    ctx.targets.programs.get(KEYS.program)!.adminKeys = [ADMIN];
    return ctx;
}

let slot = 1;
function run(ctx: DetectorContext, instructions: IxSpec[], options: TxOptions = { feePayer: ADMIN }) {
    return adminKeyBehavior.detect(tx(`sig-${slot}`, slot++, instructions, options), ctx);
}

/** An undecoded call whose first data byte is its instruction tag, as on Raydium AMM v4. */
const tagged = (tag: number): IxSpec => ({
    programId: KEYS.program,
    name: null,
    raw: { data: new Uint8Array([tag, 1, 2, 3]), accounts: [ADMIN] },
});

/** A withdraw whose inner token transfer is signed by a per-call PDA, as Pump.fun's are. */
const withdraw = (pda: string): IxSpec => ({
    ...tagged(9),
    inner: [{ programId: PROGRAMS.splToken, name: 'transfer', accounts: [['owner_or_delegate', pda, true]] }],
});
const pay = (from: string): IxSpec => ({ programId: PROGRAMS.system, name: 'transfer', accounts: [['funding_account', from, true]] });
const flashLoan: IxSpec = { programId: MARGINFI, name: 'lending_account_start_flashloan', accounts: [['signer', KEYS.attacker, true]] };

describe('admin-key-behavior', () => {
    it('flags a known key calling an instruction its history never shows, once', () => {
        const ctx = setup();
        for (let i = 0; i < BASELINE; i++) expect(run(ctx, [tagged(i % 2 ? 6 : 13)])).toEqual([]);

        const [finding] = run(ctx, [tagged(6), tagged(7)]);
        expect(finding).toMatchObject({ severity: 'high', title: 'Admin key used in an unfamiliar way', stages: ['control'] });
        expect(finding!.description).toContain('called undecoded instruction 7, which it had not in 12 earlier transactions');
        expect(run(ctx, [tagged(7)])).toEqual([]);
    });

    it('counts a key passed to an undecoded call as signing, and flags it paying its own fee for the first time', () => {
        const ctx = setup();
        const ops = { feePayer: KEYS.member };
        for (let i = 0; i < BASELINE; i++) expect(run(ctx, [tagged(i % 2 ? 6 : 13)], ops)).toEqual([]);

        const [finding] = run(ctx, [tagged(6), tagged(7)], { feePayer: ADMIN });
        expect(finding!.severity).toBe('critical');
        expect(finding!.description).toContain('had itself paying the fee as fee payer or co-signer');
    });

    it('ignores PDAs that sign through CPI, and flags a new payer, a new program and a flash loan together as critical', () => {
        const ctx = setup();
        for (let i = 0; i < BASELINE; i++) expect(run(ctx, [pay(ADMIN), withdraw(`Pda${i}`.padEnd(43, '1'))])).toEqual([]);

        const [finding] = run(ctx, [flashLoan, pay(ADMIN), withdraw('PdaX'.padEnd(43, '1'))], { feePayer: KEYS.attacker });
        expect(finding!.severity).toBe('critical');
        expect(Object.values(finding!.details).join(' | ')).toMatch(
            /had Atta.* as fee payer or co-signer.*also called .*inside a flash loan \(lending_account_start_flashloan/,
        );
    });

    it('reports a flash loan before any baseline exists', () => {
        const [finding] = run(setup(), [flashLoan, pay(ADMIN), tagged(9)], { feePayer: KEYS.attacker });
        expect(finding).toMatchObject({ severity: 'high' });
        expect(finding!.description).toContain('inside a flash loan');
    });

    it('treats flash loans from a lending program the key already uses as routine', () => {
        const ctx = setup();
        for (let i = 0; i < BASELINE; i++) run(ctx, [flashLoan, pay(ADMIN), tagged(9)], { feePayer: KEYS.attacker });
        expect(run(ctx, [flashLoan, pay(ADMIN), tagged(9)], { feePayer: KEYS.attacker })).toEqual([]);
    });

    it('rates a new fee payer alone as low', () => {
        const ctx = setup();
        for (let i = 0; i < BASELINE; i++) run(ctx, [pay(ADMIN), tagged(9)]);
        expect(run(ctx, [pay(ADMIN), tagged(9)], { feePayer: KEYS.member })).toMatchObject([
            { severity: 'low', title: 'Admin key used with something new' },
        ]);
    });

    it('skips transactions the key appears in without signing', () => {
        const ctx = setup();
        for (let i = 0; i < BASELINE; i++) run(ctx, [pay(ADMIN), tagged(9)]);
        const referenced: IxSpec = { programId: KEYS.program, name: 'swap', accounts: [['admin', ADMIN, false]] };
        expect(run(ctx, [flashLoan, referenced], { feePayer: KEYS.attacker })).toEqual([]);
    });
});
