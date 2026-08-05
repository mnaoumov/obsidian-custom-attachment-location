import { basename } from 'obsidian-dev-utils/path';
import { escapeRegExp } from 'obsidian-dev-utils/reg-exp';

interface IsReferencedByRawPathParams {
  /**
   * The vault-relative path of the attachment being collected.
   */
  readonly attachmentPath: string;

  /**
   * The raw text of a candidate note (as returned by `Vault.cachedRead`).
   */
  readonly content: string;
}

/**
 * Heuristically detects whether `content` references the attachment via its raw path or file name -
 * the kind of reference Obsidian does NOT index (e.g. a third-party plugin's custom embed syntax, a
 * raw HTML `<img src>`, or a plain path inside a code block).
 *
 * The check errs toward reporting a reference (a false positive merely leaves an attachment
 * un-collected, whereas a false negative could relocate a still-used attachment and lose it):
 * - a needle that contains a `/` (a vault-relative path) is matched as a plain substring, which is
 *   specific enough to avoid unrelated hits;
 * - a needle without a `/` (a bare file name) is matched only when it is NOT preceded by another
 *   path/name character, so `img.png` does not spuriously match `myimg.png` or `sub/img.png`;
 * - URL-encoded forms (e.g. `my%20img.png`) are matched too.
 */
export function isReferencedByRawPath(params: IsReferencedByRawPathParams): boolean {
  const { attachmentPath, content } = params;
  const fileName = basename(attachmentPath);

  const needles = new Set<string>([attachmentPath, encodeURI(attachmentPath), encodeURI(fileName), fileName]);

  for (const needle of needles) {
    if (needle === '') {
      continue;
    }

    if (needle.includes('/')) {
      if (content.includes(needle)) {
        return true;
      }

      continue;
    }

    // A bare file name: require a boundary so a longer name (e.g. `myimg.png` or `sub/img.png`) does not match.
    const boundedRegExp = new RegExp(String.raw`(?<![\w./\\-])${escapeRegExp(needle)}`, 'u');
    if (boundedRegExp.test(content)) {
      return true;
    }
  }

  return false;
}
