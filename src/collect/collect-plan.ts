/**
 * @file
 *
 * The plan a folder or vault collect shows before it applies: every attachment it examined, where it would go, how,
 * and every conflict. The planner in `attachment-collector.ts` fills it without writing anything; this module holds
 * the shape, the pure classification and conflict rules, and the dialog content.
 *
 * Ported from the plan preview of `Attachment Organizer` (https://github.com/kiteruunner/obsidian-attachment-organizer),
 * MIT License, Copyright (c) 2025 Kirun. Only the idea of a categorized plan reviewed before **Apply plan** is taken;
 * no code was copied.
 */

import { appendCodeBlock } from '@mnaoumov/obsidian-lib/html-element';
import { t } from '@mnaoumov/obsidian-lib/i18n/i18n';
import { dirname } from '@mnaoumov/typescript-lib/path';

import {
  codeNode,
  translateFragment
} from '../i18n/translate-fragment.ts';

/**
 * Why a planned destination conflicts.
 */
export enum CollectPlanConflictReason {
  /**
   * Another file already sits at the destination.
   */
  DestinationTaken = 'DestinationTaken',

  /**
   * An earlier entry of the plan claims the same destination for a different attachment.
   */
  SameDestination = 'SameDestination'
}

/**
 * What the collect would do to one attachment of one note.
 */
export enum CollectPlanEntryKind {
  /**
   * Copied for this note, the original staying for the other notes that use it.
   */
  Copy = 'Copy',

  /**
   * Already where this note would put it.
   */
  Keep = 'Keep',

  /**
   * Its destination already holds the same bytes, so the note is pointed at that file and this one goes.
   */
  Merge = 'Merge',

  /**
   * Moved to another folder, renamed or not.
   */
  Move = 'Move',

  /**
   * Renamed where it is.
   */
  Rename = 'Rename',

  /**
   * Referenced by several notes with no owner decided, so the collect asks, or cancels, when it reaches it.
   */
  Shared = 'Shared',

  /**
   * Left alone, for the reason the entry names.
   */
  Skip = 'Skip'
}

/**
 * Why the collect leaves an attachment alone.
 */
export enum CollectPlanSkipReason {
  /**
   * Its path matches `Exclude paths from attachment collecting`.
   */
  Excluded = 'Excluded',

  /**
   * A note names it by a raw path the metadata cache does not index.
   */
  RawPath = 'RawPath',

  /**
   * Several notes reference it and the multiple-notes mode is `Skip`.
   */
  Shared = 'Shared',

  /**
   * It sits in an attachment unit folder that several notes reference.
   */
  UnitFolderShared = 'UnitFolderShared'
}

/**
 * Parameters for {@link buildCollectPlanMessage}.
 */
export interface BuildCollectPlanMessageParams {
  /**
   * The folders and notes the user asked to collect, which the message names first, as the confirm always did.
   */
  readonly abstractFilePaths: readonly string[];

  /**
   * The most entries to list; the rest are counted.
   */
  readonly maxListedEntries?: number;

  /**
   * The plan.
   */
  readonly plan: CollectPlan;
}

/**
 * The whole plan.
 */
export interface CollectPlan {
  readonly conflicts: readonly CollectPlanConflict[];
  readonly entries: readonly CollectPlanEntry[];
}

/**
 * One conflict of the plan.
 */
export interface CollectPlanConflict {
  /**
   * The entry whose destination conflicts.
   */
  readonly entry: CollectPlanEntry;

  /**
   * The attachment of the earlier entry claiming the same destination, for {@link CollectPlanConflictReason.SameDestination}.
   */
  readonly otherAttachmentPath: null | string;

  /**
   * Why it conflicts.
   */
  readonly reason: CollectPlanConflictReason;
}

/**
 * One attachment of one note in the plan.
 */
export interface CollectPlanEntry {
  /**
   * The attachment's current path; for a unit folder, the folder's.
   */
  readonly attachmentPath: string;

  /**
   * Whether {@link attachmentPath} is an attachment unit folder that travels whole.
   */
  readonly isUnitFolder: boolean;

  /**
   * What the collect would do.
   */
  readonly kind: CollectPlanEntryKind;

  /**
   * The note being collected.
   */
  readonly notePath: string;

  /**
   * The note that wins the attachment on priority, when it is not the one being collected.
   */
  readonly ownerNotePath: null | string;

  /**
   * Why it is left alone, for {@link CollectPlanEntryKind.Skip}.
   */
  readonly skipReason: CollectPlanSkipReason | null;

  /**
   * Where it would go, or `null` when it stays.
   */
  readonly targetPath: null | string;
}

const DEFAULT_MAX_LISTED_ENTRIES = 500;

const KINDS_THAT_WRITE_A_DESTINATION: ReadonlySet<CollectPlanEntryKind> = new Set([
  CollectPlanEntryKind.Copy,
  CollectPlanEntryKind.Move,
  CollectPlanEntryKind.Rename
]);

/**
 * Parameters for {@link createSkippedCollectPlanEntry}.
 */
export interface CreateSkippedCollectPlanEntryParams {
  readonly attachmentPath: string;
  readonly notePath: string;
  readonly skipReason: CollectPlanSkipReason;
}

/**
 * Builds the dialog content for a plan: the folders asked for, the counts, the conflicts, and the entries that change
 * something, grouped by note.
 *
 * Entries already in place are only counted: in a vault collected before, they are nearly all of them.
 *
 * @param params - The plan and what was asked for.
 * @returns The dialog content.
 */
export function buildCollectPlanMessage(params: BuildCollectPlanMessageParams): DocumentFragment {
  const maxListedEntries = params.maxListedEntries ?? DEFAULT_MAX_LISTED_ENTRIES;
  return createFragment((f) => {
    f.append(translateFragment(($) => $.attachmentCollector.confirm, {
      folders: (parent) => {
        parent.createEl('ul', {}, (ul) => {
          for (const path of params.abstractFilePaths) {
            ul.createEl('li', {}, (li) => {
              appendCodeBlock(li, path);
            });
          }
        });
      }
    }));

    const counts = countCollectPlanEntries(params.plan.entries);
    f.createEl('p', {
      cls: 'custom-attachment-location-collect-plan-summary',
      text: t(($) => $.attachmentCollector.plan.summary, {
        copyCount: counts.get(CollectPlanEntryKind.Copy) ?? 0,
        keepCount: counts.get(CollectPlanEntryKind.Keep) ?? 0,
        mergeCount: counts.get(CollectPlanEntryKind.Merge) ?? 0,
        moveCount: counts.get(CollectPlanEntryKind.Move) ?? 0,
        renameCount: counts.get(CollectPlanEntryKind.Rename) ?? 0,
        sharedCount: counts.get(CollectPlanEntryKind.Shared) ?? 0,
        skipCount: counts.get(CollectPlanEntryKind.Skip) ?? 0
      })
    });

    if (params.plan.conflicts.length > 0) {
      f.createEl('p', { text: t(($) => $.attachmentCollector.plan.conflictsHeading, { count: params.plan.conflicts.length }) });
      f.createEl('ul', { cls: 'custom-attachment-location-collect-plan-conflicts' }, (ul) => {
        for (const conflict of params.plan.conflicts.slice(0, maxListedEntries)) {
          ul.createEl('li', {}, (li) => {
            li.append(renderConflict(conflict));
          });
        }
      });
    }

    const listedEntries = params.plan.entries.filter((entry) => entry.kind !== CollectPlanEntryKind.Keep);
    if (listedEntries.length === 0) {
      f.createEl('p', { text: t(($) => $.attachmentCollector.plan.noChanges) });
    } else {
      renderEntriesByNote(f, listedEntries.slice(0, maxListedEntries));
      if (listedEntries.length > maxListedEntries) {
        f.createEl('p', { text: t(($) => $.attachmentCollector.plan.moreEntries, { count: listedEntries.length - maxListedEntries }) });
      }
    }

    f.createEl('p', { text: t(($) => $.attachmentCollector.plan.previewNote) });
  });
}

/**
 * Tells a move from a rename: an attachment that keeps its folder is renamed.
 *
 * @param attachmentPath - The current path.
 * @param targetPath - The planned path.
 * @returns {@link CollectPlanEntryKind.Rename} or {@link CollectPlanEntryKind.Move}.
 */
export function classifyCollectMove(attachmentPath: string, targetPath: string): CollectPlanEntryKind {
  return dirname(attachmentPath) === dirname(targetPath) ? CollectPlanEntryKind.Rename : CollectPlanEntryKind.Move;
}

/**
 * Counts the entries of each kind.
 *
 * @param entries - The plan's entries.
 * @returns The count of each kind present.
 */
export function countCollectPlanEntries(entries: readonly CollectPlanEntry[]): Map<CollectPlanEntryKind, number> {
  const counts = new Map<CollectPlanEntryKind, number>();
  for (const entry of entries) {
    counts.set(entry.kind, (counts.get(entry.kind) ?? 0) + 1);
  }
  return counts;
}

/**
 * Builds the entry of an attachment the collect leaves alone.
 *
 * @param params - The attachment, its note and the reason.
 * @returns The entry.
 */
export function createSkippedCollectPlanEntry(params: CreateSkippedCollectPlanEntryParams): CollectPlanEntry {
  return {
    attachmentPath: params.attachmentPath,
    isUnitFolder: false,
    kind: CollectPlanEntryKind.Skip,
    notePath: params.notePath,
    ownerNotePath: null,
    skipReason: params.skipReason,
    targetPath: null
  };
}

/**
 * Finds every destination the collect cannot take as planned.
 *
 * A destination another file holds, or one an earlier entry already claims for a different attachment, is still
 * collected into, under a duplicate-name suffix. That changes the name the user reviewed, so it is a conflict. An entry
 * repeating an earlier one (the same attachment to the same place, from another note) is not: the second does nothing.
 * A destination held by the attachment that an earlier entry moves away is still reported, because the order the
 * collect takes is the notes' order and the plan does not replay it.
 *
 * @param entries - The plan's entries, in the collect's order.
 * @param isPathTaken - Whether a file or folder sits at a path now.
 * @returns The conflicts, in the entries' order.
 */
export function findCollectPlanConflicts(entries: readonly CollectPlanEntry[], isPathTaken: (path: string) => boolean): CollectPlanConflict[] {
  const conflicts: CollectPlanConflict[] = [];
  const claimedDestinations = new Map<string, string>();

  for (const entry of entries) {
    if (!entry.targetPath || !KINDS_THAT_WRITE_A_DESTINATION.has(entry.kind)) {
      continue;
    }

    const key = entry.targetPath.toLowerCase();
    const claimingAttachmentPath = claimedDestinations.get(key);
    if (claimingAttachmentPath !== undefined) {
      if (claimingAttachmentPath !== entry.attachmentPath) {
        conflicts.push({ entry, otherAttachmentPath: claimingAttachmentPath, reason: CollectPlanConflictReason.SameDestination });
      }
      continue;
    }

    claimedDestinations.set(key, entry.attachmentPath);
    if (isPathTaken(entry.targetPath)) {
      conflicts.push({ entry, otherAttachmentPath: null, reason: CollectPlanConflictReason.DestinationTaken });
    }
  }

  return conflicts;
}

/**
 * Drops an entry that repeats an earlier one: the same attachment, to the same destination, the same way. Every note
 * referencing an attachment the priority list hands to one owner plans that one move, and the collect makes it once:
 * by the time it reaches the second note, the attachment is already there.
 *
 * An entry that writes nothing (kept, skipped, asked about) is never a repeat, because it says something about its own
 * note.
 *
 * @param entries - The plan's entries, in the collect's order.
 * @returns The entries without the repeats.
 */
export function removeRepeatedCollectPlanEntries(entries: readonly CollectPlanEntry[]): CollectPlanEntry[] {
  const seen = new Set<string>();
  const result: CollectPlanEntry[] = [];
  for (const entry of entries) {
    const key = JSON.stringify([entry.attachmentPath, entry.targetPath, entry.kind]);
    if (entry.targetPath !== null && entry.kind !== CollectPlanEntryKind.Shared && seen.has(key)) {
      continue;
    }
    seen.add(key);
    result.push(entry);
  }
  return result;
}

function getKindLabel(kind: CollectPlanEntryKind): string {
  switch (kind) {
    case CollectPlanEntryKind.Copy: {
      return t(($) => $.attachmentCollector.plan.kind.copy);
    }
    case CollectPlanEntryKind.Merge: {
      return t(($) => $.attachmentCollector.plan.kind.merge);
    }
    case CollectPlanEntryKind.Move: {
      return t(($) => $.attachmentCollector.plan.kind.move);
    }
    case CollectPlanEntryKind.Rename: {
      return t(($) => $.attachmentCollector.plan.kind.rename);
    }
    case CollectPlanEntryKind.Shared: {
      return t(($) => $.attachmentCollector.plan.kind.shared);
    }
    case CollectPlanEntryKind.Skip: {
      return t(($) => $.attachmentCollector.plan.kind.skip);
    }
    default: {
      throw new Error(`Unknown collect plan entry kind: ${kind}`);
    }
  }
}

function getSkipReasonLabel(reason: CollectPlanSkipReason): string {
  switch (reason) {
    case CollectPlanSkipReason.Excluded: {
      return t(($) => $.attachmentCollector.plan.skipReason.excluded);
    }
    case CollectPlanSkipReason.RawPath: {
      return t(($) => $.attachmentCollector.plan.skipReason.rawPath);
    }
    case CollectPlanSkipReason.Shared: {
      return t(($) => $.attachmentCollector.plan.skipReason.shared);
    }
    case CollectPlanSkipReason.UnitFolderShared: {
      return t(($) => $.attachmentCollector.plan.skipReason.unitFolderShared);
    }
    default: {
      throw new Error(`Unknown collect plan skip reason: ${String(reason)}`);
    }
  }
}

function renderConflict(conflict: CollectPlanConflict): DocumentFragment {
  const target = codeNode(conflict.entry.targetPath ?? '');
  const attachment = codeNode(conflict.entry.attachmentPath);
  switch (conflict.reason) {
    case CollectPlanConflictReason.DestinationTaken: {
      return translateFragment(($) => $.attachmentCollector.plan.conflict.destinationTaken, { attachment, target });
    }
    case CollectPlanConflictReason.SameDestination: {
      return translateFragment(($) => $.attachmentCollector.plan.conflict.sameDestination, {
        attachment,
        otherAttachment: codeNode(conflict.otherAttachmentPath ?? ''),
        target
      });
    }
    default: {
      throw new Error(`Unknown collect plan conflict reason: ${String(conflict.reason)}`);
    }
  }
}

function renderEntriesByNote(parent: DocumentFragment, entries: readonly CollectPlanEntry[]): void {
  const entriesByNote = new Map<string, CollectPlanEntry[]>();
  for (const entry of entries) {
    let noteEntries = entriesByNote.get(entry.notePath);
    if (!noteEntries) {
      noteEntries = [];
      entriesByNote.set(entry.notePath, noteEntries);
    }
    noteEntries.push(entry);
  }

  parent.createDiv({ cls: 'custom-attachment-location-collect-plan-notes' }, (div) => {
    for (const [notePath, noteEntries] of entriesByNote) {
      div.createEl('details', {}, (details) => {
        details.createEl('summary', {}, (summary) => {
          appendCodeBlock(summary, notePath);
          summary.appendText(` (${String(noteEntries.length)})`);
        });
        details.createEl('ul', {}, (ul) => {
          for (const entry of noteEntries) {
            ul.createEl('li', { attr: { 'data-kind': entry.kind } }, (li) => {
              renderEntry(li, entry);
            });
          }
        });
      });
    }
  });
}

function renderEntry(li: HTMLElement, entry: CollectPlanEntry): void {
  li.appendText(`${getKindLabel(entry.kind)}: `);
  appendCodeBlock(li, entry.attachmentPath);
  if (entry.targetPath) {
    li.appendText(' → ');
    appendCodeBlock(li, entry.targetPath);
  }
  if (entry.skipReason) {
    li.appendText(` (${getSkipReasonLabel(entry.skipReason)})`);
  }
  if (!entry.ownerNotePath) {
    return;
  }

  li.appendText(' (');
  li.append(translateFragment(($) => $.attachmentCollector.plan.ownerNote, { note: codeNode(entry.ownerNotePath) }));
  li.appendText(')');
}
