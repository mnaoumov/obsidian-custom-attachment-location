/**
 * @file
 *
 * The Prism language the plugin's tokenized-string settings are highlighted as.
 *
 * The grammar itself is `TemplatesLanguageComponent` in `obsidian-dev-utils`: the `{{token:format}}` syntax is
 * Obsidian core's own Templates language, shared by every plugin that extends it. What is this plugin's own is the
 * language id, the shape of the format half, and the two path tokens its templates carry.
 */

import type { PrismTokenObject } from '@obsidian-typings/obsidian-public-latest';

import { TemplatesLanguageComponent } from 'obsidian-dev-utils/obsidian/components/templates-language-component';

/**
 * The Prism language the settings tab's template fields are highlighted as.
 */
export const TOKENIZED_STRING_LANGUAGE = 'custom-attachment-location-tokenized-string';

const OBJECT_PREFIX_PATTERN = String.raw`\{(?:[^{}]|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'`;
const OBJECT_SUFFIX_PATTERN = String.raw`)*\}`;
const FORMAT_OBJECT_DEPTH_1 = `${OBJECT_PREFIX_PATTERN}${OBJECT_SUFFIX_PATTERN}`;
// Depth 2: allows depth-1 blocks inside.
const FORMAT_OBJECT_DEPTH_2 = `${OBJECT_PREFIX_PATTERN}|${FORMAT_OBJECT_DEPTH_1}${OBJECT_SUFFIX_PATTERN}`;
// Depth 3: allows depth-2 blocks inside.
const FORMAT_OBJECT_DEPTH_3 = `${OBJECT_PREFIX_PATTERN}|${FORMAT_OBJECT_DEPTH_2}${OBJECT_SUFFIX_PATTERN}`;

/**
 * The extent of the format half: a JSON5 object (`{{date:{momentJsFormat:'YYYY'}}}`), or the scalar shorthand
 * (`{{date:YYYY-MM-DD}}`), which the parser accepts as any text free of braces.
 *
 * The object alternative emulates brace depth up to three, since a regexp cannot count. That is deep enough for a
 * `{{prompt:{defaultValueTemplate:'{{...}}'}}}` template, whose inner template sits in a string literal anyway. The
 * parser does not rely on this pattern: it finds the object's extent with acorn.
 */
export const TOKENIZED_STRING_FORMAT_PATTERN = new RegExp(`^(?:${FORMAT_OBJECT_DEPTH_3}|[^{}]+)`);

const OBJECT_FORMAT_PATTERN = new RegExp(`^(?:${FORMAT_OBJECT_DEPTH_3})`);
const SCALAR_FORMAT_PATTERN = /^[^{}]+/;

/**
 * Creates the component registering the {@link TOKENIZED_STRING_LANGUAGE} grammar.
 *
 * The format half is structured, because an object format nests the `javascript` grammar; the factory form hands
 * that grammar over from the loaded Prism module. `requirePrismLanguage` throws when `javascript` is missing, since a
 * missing built-in grammar means Prism did not load as expected.
 *
 * The shared component emits ONE `format` entry, so the two shapes split inside it: the object format nests
 * `javascript`, and the scalar format reads as a string, the way core's own `{{date:YYYY-MM-DD}}` does.
 *
 * @returns The component.
 */
export function createTokenizedStringLanguageComponent(): TemplatesLanguageComponent {
  return new TemplatesLanguageComponent({
    extraGrammar: {
      important: {
        pattern: /^\./
      },
      operator: {
        alias: 'entity',
        pattern: /\//
      }
    },
    formatSource: (params): PrismTokenObject => ({
      inside: {
        objectFormat: {
          alias: 'language-javascript',
          inside: params.requirePrismLanguage('javascript'),
          pattern: OBJECT_FORMAT_PATTERN
        },
        scalarFormat: {
          alias: 'string',
          pattern: SCALAR_FORMAT_PATTERN
        }
      },
      pattern: TOKENIZED_STRING_FORMAT_PATTERN
    }),
    language: TOKENIZED_STRING_LANGUAGE
  });
}
