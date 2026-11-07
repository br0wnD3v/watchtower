import { short } from '../format.js';
import type { ChainSignal } from '../state.js';
import { txFinding, type AttackStage, type DetectorContext, type Finding, type FindingAnchor } from './types.js';

export const ATTACK_CHAIN_ID = 'attack-chain';
const WINDOW_SECONDS = 24 * 3_600;
const STAGE_TEXT: Record<AttackStage, string> = { control: 'control changed', risk: 'risk settings changed', drain: 'funds moved out' };
const STAGE_ORDER: AttackStage[] = ['control', 'risk', 'drain'];
const TIMELINE_ENTRIES = 6;

/** One critical finding per protocol for each new combination of linked stages within the window. */
export function linkAttackStages(tx: FindingAnchor, findings: Finding[], ctx: DetectorContext): Finding[] {
    const windowSlots = Math.round((WINDOW_SECONDS * 1000) / ctx.slotMs);
    const chains: Finding[] = [];
    const byGroup = new Map<string, ChainSignal[]>();
    for (const finding of findings) {
        const group = ctx.targets.groups.get(finding.subject) ?? finding.subject;
        for (const stage of finding.stages ?? []) {
            byGroup.set(
                group,
                ctx.state.recordChainSignal(group, { stage, findingId: finding.id, title: finding.title, slot: finding.slot }, windowSlots),
            );
        }
    }
    for (const [group, signals] of byGroup) {
        const stages = new Set(signals.map((s) => s.stage));
        const linked = stages.size >= 2 && (stages.has('drain') || (stages.has('control') && stages.has('risk')));
        const key = [...stages].sort().join('+');
        if (!linked || !ctx.state.claimWindowAlert(`chain:${group}:${key}`, tx.slot, windowSlots)) continue;

        const timeline = steps(signals);
        const shown = timeline.slice(0, TIMELINE_ENTRIES);
        const label = labelOf(group, ctx);
        chains.push(
            txFinding(ATTACK_CHAIN_ID, tx, group, {
                severity: 'critical',
                title: 'Possible attack in progress',
                description: `${label}: ${STAGE_ORDER.filter((s) => stages.has(s))
                    .map((s) => STAGE_TEXT[s])
                    .join(', ')} within 24 hours. ${collapse(timeline.map((s) => s.title)).join(' → ')}. Review these together now.`,
                subject: group,
                subjectLabel: label,
                details: Object.fromEntries(
                    shown.map((s, i) => [`${i + 1}. ${s.stages.join(' + ')}`, `${s.title} (slot ${s.slot.toLocaleString('en-US')})`]),
                ),
            }),
        );
    }
    return chains;
}

/** Merges consecutive repeats into one entry with a count. */
function collapse(titles: string[]): string[] {
    const runs: { title: string; count: number }[] = [];
    for (const title of titles) {
        const last = runs.at(-1);
        if (last?.title === title) last.count++;
        else runs.push({ title, count: 1 });
    }
    return runs.map((r) => (r.count > 1 ? `${r.title} ×${r.count}` : r.title));
}

/** One entry per finding, oldest first. */
function steps(signals: ChainSignal[]): { title: string; slot: number; stages: AttackStage[] }[] {
    const byFinding = new Map<string, { title: string; slot: number; stages: AttackStage[] }>();
    for (const s of [...signals].sort((a, b) => a.slot - b.slot)) {
        const step = byFinding.get(s.findingId) ?? { title: s.title, slot: s.slot, stages: [] };
        step.stages.push(s.stage);
        byFinding.set(s.findingId, step);
    }
    return [...byFinding.values()];
}

function labelOf(group: string, ctx: DetectorContext): string {
    const { programs, multisigs, treasuries, mints } = ctx.targets;
    return (
        programs.get(group)?.label ?? multisigs.get(group)?.label ?? treasuries.get(group)?.label ?? mints.get(group)?.label ?? short(group)
    );
}
