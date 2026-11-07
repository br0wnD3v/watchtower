import type { Severity } from './config.js';
import { maxSeverity } from './detectors/severity.js';
import { txFinding, type AttackStage, type Finding, type FindingAnchor } from './detectors/types.js';
import { decodeConfig, type ConfigAccount } from './discover/index.js';
import type { ConfigField } from './discover/idl.js';
import type { AlertMode } from './engine.js';
import type { Runtime } from './runtime.js';

export const CONFIG_CHANGE_ID = 'config-change';
const MAX_ACCOUNTS_PER_CALL = 100;

interface Rule {
    severity: Severity;
    stage?: AttackStage;
}

function ruleFor(field: ConfigField): Rule | null {
    const name = field.name.toLowerCase();
    if (field.admin) return { severity: 'critical', stage: 'control' };
    if (/padding|reserved|bump|cached/.test(name)) return null;
    if (field.type === 'pubkey') return { severity: 'high', stage: 'risk' };
    if (/pause|halt|emergency|frozen|status|mode|enabled|disabled/.test(name)) return { severity: 'high', stage: 'risk' };
    if (/limit|weight|ltv|ratio|cap|max|min|threshold|liquidation|fee|margin|leverage|borrow|deposit|withdraw/.test(name)) {
        return { severity: 'medium', stage: 'risk' };
    }
    return null;
}

const inFlight = new WeakMap<Runtime, Promise<unknown>>();

/** Runs one at a time per runtime, so reads are compared in order. The first read of an account only sets its baseline. */
export function checkConfigChanges(runtime: Runtime, mode: AlertMode): Promise<number> {
    const run = (inFlight.get(runtime) ?? Promise.resolve()).catch(() => undefined).then(() => check(runtime, mode));
    inFlight.set(runtime, run);
    return run;
}

async function check(runtime: Runtime, mode: AlertMode): Promise<number> {
    const accounts = runtime.discovery.programs.flatMap((p) => p.configAccounts.map((account) => ({ account, programId: p.programId })));
    let recorded = 0;
    for (let i = 0; i < accounts.length; i += MAX_ACCOUNTS_PER_CALL) {
        const batch = accounts.slice(i, i + MAX_ACCOUNTS_PER_CALL);
        const { slot, data } = await runtime.rpc.getMultipleAccountsData(batch.map((b) => b.account.address));
        const anchor: FindingAnchor = { signature: null, slot, blockTime: Math.floor(Date.now() / 1000) };
        const findings: Finding[] = [];
        batch.forEach(({ account, programId }, j) => {
            const bytes = data[j];
            if (!bytes) return;
            const previous = runtime.state.configRead(account.address);
            // An RPC node behind the last read would report the change backwards.
            if (previous && slot < previous.slot) return;
            const values = decodeConfig(bytes, account.layout);
            runtime.state.setConfigRead(account.address, slot, values);
            const finding = previous ? configFinding(runtime, programId, account, previous.values, values, anchor) : null;
            if (finding) findings.push(finding);
        });
        if (findings.length > 0) recorded += await runtime.engine.recordLinked(findings, mode, anchor);
    }
    runtime.state.save();
    return recorded;
}

function configFinding(
    runtime: Runtime,
    programId: string,
    account: ConfigAccount,
    previous: Record<string, string>,
    values: Record<string, string>,
    anchor: FindingAnchor,
): Finding | null {
    const changes = account.layout.fields.flatMap((field) => {
        const before = previous[field.name];
        const after = values[field.name];
        const rule = before !== undefined && after !== undefined && before !== after ? ruleFor(field) : null;
        return rule ? [{ field, before: before!, after: after!, rule }] : [];
    });
    if (changes.length === 0) return null;

    const program = runtime.ctx.targets.programs.get(programId);
    const label = program?.label ?? programId;
    const severity = maxSeverity(...changes.map((c) => c.rule.severity));
    const stages = [...new Set(changes.flatMap((c) => (c.rule.stage ? [c.rule.stage] : [])))];
    const admin = changes.find((c) => c.field.admin);
    const name = account.layout.account;
    return txFinding(CONFIG_CHANGE_ID, anchor, account.address, {
        severity,
        title: admin ? `Admin changed in ${name}.${admin.field.name}` : `${name} settings changed`,
        description: `${label}'s ${name} account ${account.address} changed: ${changes.map((c) => `${c.field.name} ${c.before} → ${c.after}`).join('; ')}.`,
        subject: programId,
        subjectLabel: label,
        details: {
            Account: `${name} ${account.address}`,
            ...Object.fromEntries(changes.map((c) => [c.field.name, `${c.before} → ${c.after}`])),
        },
        ...(stages.length > 0 ? { stages } : {}),
    });
}
