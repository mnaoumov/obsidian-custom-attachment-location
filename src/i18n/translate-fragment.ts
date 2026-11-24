/**
 * @file
 *
 * Renders one whole translated sentence whose placeholders are DOM nodes: a code span, a link, a list or any other
 * element. Translators get the sentence whole and move each placeholder wherever their language needs it, instead of
 * translating `part1`, `part2`... fragments that the code stitches back together in English order.
 */

import type { TranslationNode } from '@mnaoumov/obsidian-lib/i18n/t-fragment';
import type { SelectorParam } from 'i18next';

import { appendCodeBlock } from '@mnaoumov/obsidian-lib/html-element';
import { tFragment } from '@mnaoumov/obsidian-lib/i18n/t-fragment';
import { castTo } from '@mnaoumov/typescript-lib/object-utils';

export type { TranslationNode } from '@mnaoumov/obsidian-lib/i18n/t-fragment';

/**
 * A placeholder rendered as a code span.
 *
 * @param code - The code text.
 * @returns The placeholder node builder.
 */
export function codeNode(code: string): TranslationNode {
  return (parent) => {
    appendCodeBlock(parent, code);
  };
}

/**
 * A placeholder rendered as a link.
 *
 * @param href - The link target.
 * @param text - The link text.
 * @returns The placeholder node builder.
 */
export function linkNode(href: string, text: string): TranslationNode {
  return (parent) => {
    parent.createEl('a', { href, text });
  };
}

/**
 * Translates a sentence like `tFragment` from `@mnaoumov/obsidian-lib`, and renders each line break of the
 * translation as a `<br>`, so a description of several lines is still one string to translate.
 *
 * @param selector - The translation selector.
 * @param nodes - The DOM values of the placeholders, by placeholder name.
 * @param options - The `i18next` options, including the plain values of the other placeholders.
 * @returns A fragment holding the translated text with the nodes in place.
 */
export function translateFragment(
  selector: SelectorParam,
  nodes: Readonly<Record<string, TranslationNode>> = {},
  options?: Readonly<Record<string, unknown>>
): DocumentFragment {
  const fragment = tFragment(selector, nodes, options);
  // Live iteration is safe: a replacement holds no line break, so the loop steps over it.
  for (const child of fragment.childNodes) {
    if (child.nodeType !== Node.TEXT_NODE) {
      continue;
    }

    const text = castTo<Text>(child).data;
    if (!text.includes('\n')) {
      continue;
    }

    const lines = text.split('\n');
    const replacement = createFragment((f) => {
      for (const [index, line] of lines.entries()) {
        if (index > 0) {
          f.createEl('br');
        }
        if (line) {
          f.appendText(line);
        }
      }
    });
    child.replaceWith(replacement);
  }
  return fragment;
}
