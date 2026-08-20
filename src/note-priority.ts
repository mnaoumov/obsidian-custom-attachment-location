/**
 * @file
 *
 * Decides which of several notes referencing the same attachment owns it.
 *
 * An attachment referenced from more than one note has no single correct home, so collecting it falls
 * back to whatever `collectAttachmentUsedByMultipleNotesMode` says — skip, copy, cancel, or ask. A
 * priority list lets the user answer the question once instead: put `.md` above `.excalidraw` and an
 * image shared by both lands in the markdown note's folder.
 *
 * A tie is deliberately NOT resolved here. Two notes of equal priority is exactly the ambiguity the
 * existing mode setting already exists to handle, and inventing a second, silent rule for it would
 * move a file the user never named.
 */

import { isValidRegExp } from 'obsidian-dev-utils/reg-exp';

const PROPERTY_PREFIX = 'property:';
const REG_EXP_DELIMITER = '/';
const EXTENSION_PREFIX = '.';
const PROPERTY_VALUE_SEPARATOR = '=';

/**
 * Parameters for {@link findNotePriorityRank}.
 */
export interface FindNotePriorityRankParams {
  /**
   * The priority list, highest priority first.
   */
  readonly entries: readonly string[];

  /**
   * The note's frontmatter, or `null` when it has none.
   */
  readonly frontmatter: null | Readonly<Record<string, unknown>>;

  /**
   * The vault-relative path of the note.
   */
  readonly notePath: string;
}

/**
 * Parameters for {@link pickHighestPriorityNotePath}.
 */
export interface PickHighestPriorityNotePathParams {
  /**
   * The vault-relative paths of the notes referencing the attachment.
   */
  readonly notePaths: readonly string[];

  /**
   * The priority rank of a note. Lower wins; {@link NO_PRIORITY_MATCH} means the note matched nothing.
   *
   * @param notePath - The vault-relative path of the note.
   * @returns The rank.
   */
  rank(notePath: string): number;
}

/**
 * The rank of a note that matches no entry in the priority list. Higher than any real rank, so a note
 * that matches nothing always loses to one that matches something.
 */
export const NO_PRIORITY_MATCH = Infinity;

/**
 * Finds how highly a note ranks in the priority list.
 *
 * An entry matches in one of four ways, picked by its shape so that one list can express all of them:
 *
 * - `property:name` — the note's frontmatter has `name`; `property:name=value` also compares the value.
 * - `/regular expression/` — tested against the note's path.
 * - `.ext` — the note's path ends with it, case-insensitively. This is the form the request asked for.
 * - anything else — a path from the vault root, matching the vocabulary of the include / exclude
 *   path settings.
 *
 * When a note matches several entries the **longest** one decides its rank, so the most specific
 * entry wins and the order of the list is left to express priority. Without this an Excalidraw note
 * could never rank below a plain markdown one: `drawing.excalidraw.md` also ends with `.md`, so
 * `.md` above `.excalidraw.md` — the very example the request is built on — would tie instead of
 * resolving. Equal-length matches fall to the earlier entry.
 *
 * @param params - The parameters for finding the rank.
 * @returns The index of the most specific matching entry, or {@link NO_PRIORITY_MATCH} when none match.
 */
export function findNotePriorityRank(params: FindNotePriorityRankParams): number {
  let bestRank = NO_PRIORITY_MATCH;
  let bestLength = -1;

  for (const [index, entry] of params.entries.entries()) {
    // A shorter entry can never beat one that already matched, so it is not worth testing.
    if (entry.length <= bestLength) {
      continue;
    }

    if (!checkEntryMatches(entry, params)) {
      continue;
    }

    bestRank = index;
    bestLength = entry.length;
  }

  return bestRank;
}

/**
 * Picks the single highest-priority note among those referencing an attachment.
 *
 * Returns `null` when the best rank is shared by more than one note, or when no note matches
 * anything. Both are ties, and a tie is the caller's problem: it is what the multiple-notes mode
 * setting is for.
 *
 * @param params - The parameters for picking the note.
 * @returns The winning note's path, or `null` when there is no single winner.
 */
export function pickHighestPriorityNotePath(params: PickHighestPriorityNotePathParams): null | string {
  let bestRank = NO_PRIORITY_MATCH;
  let bestNotePath: null | string = null;
  let bestCount = 0;

  for (const notePath of params.notePaths) {
    const currentRank = params.rank(notePath);
    if (currentRank < bestRank) {
      bestRank = currentRank;
      bestNotePath = notePath;
      bestCount = 1;
    } else if (currentRank === bestRank) {
      bestCount++;
    }
  }

  if (bestCount !== 1 || bestRank === NO_PRIORITY_MATCH) {
    return null;
  }

  return bestNotePath;
}

function checkEntryMatches(entry: string, params: FindNotePriorityRankParams): boolean {
  if (!entry) {
    return false;
  }

  if (entry.startsWith(PROPERTY_PREFIX)) {
    return checkPropertyMatches(entry.slice(PROPERTY_PREFIX.length), params.frontmatter);
  }

  if (entry.length > 1 && entry.startsWith(REG_EXP_DELIMITER) && entry.endsWith(REG_EXP_DELIMITER)) {
    const source = entry.slice(1, -1);
    // An unparseable expression must not throw mid-collection; it simply matches nothing.
    return isValidRegExp(source) && new RegExp(source).test(params.notePath);
  }

  if (entry.startsWith(EXTENSION_PREFIX)) {
    return params.notePath.toLowerCase().endsWith(entry.toLowerCase());
  }

  const prefix = entry.endsWith('/') ? entry : `${entry}/`;
  return params.notePath === entry || params.notePath.startsWith(prefix);
}

function checkPropertyMatches(specifier: string, frontmatter: null | Readonly<Record<string, unknown>>): boolean {
  if (!frontmatter) {
    return false;
  }

  const separatorIndex = specifier.indexOf(PROPERTY_VALUE_SEPARATOR);
  if (separatorIndex === -1) {
    return Object.hasOwn(frontmatter, specifier);
  }

  const propertyName = specifier.slice(0, separatorIndex);
  const expectedValue = specifier.slice(separatorIndex + 1);
  if (!Object.hasOwn(frontmatter, propertyName)) {
    return false;
  }

  const actualValue = frontmatter[propertyName];
  // Frontmatter values are whatever YAML produced, so compare their rendering rather than requiring a
  // String. An array matches when any of its entries does, which is how tag-like properties read.
  if (Array.isArray(actualValue)) {
    return actualValue.some((item) => String(item) === expectedValue);
  }

  return String(actualValue) === expectedValue;
}
