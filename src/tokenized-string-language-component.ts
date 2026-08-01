import { SyntaxHighlightingComponent } from 'obsidian-dev-utils/obsidian/components/syntax-highlighting-component';

export const TOKENIZED_STRING_LANGUAGE = 'custom-attachment-location-tokenized-string';

/**
 * Registers the Prism language highlighting the `${token}` / `${token:format}` placeholders of the plugin's
 * tokenized-string settings.
 *
 * The language is not a code fence — it is rendered only by the `CodeHighlighterComponent` fields of the
 * settings tab, so only the Prism half of {@link SyntaxHighlightingComponent} is used.
 *
 * The grammar nests the `javascript` grammar into a `${token:{...}}` format block, which is why it is built
 * through the factory form: the factory receives the loaded Prism module, so this plugin never calls
 * `loadPrism` itself. `requirePrismLanguage` THROWS when `javascript` is missing. That replaces the silent
 * early return this component used before — a missing built-in `javascript` grammar means Prism did not load
 * as expected, and failing loudly matches the component-wide policy.
 */
export class TokenizedStringLanguageComponent extends SyntaxHighlightingComponent {
  public override async onloadAsync(): Promise<void> {
    await this.registerPrismLanguageAsync({
      grammar: (params) => {
        const javascriptLanguage = params.requirePrismLanguage('javascript');

        const PREFIX_PATTERN = String.raw`\{(?:[^{}]|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'`;
        const SUFFIX_PATTERN = String.raw`)*\}`;

        const FORMAT_OBJECT_DEPTH_1 = `${PREFIX_PATTERN}${SUFFIX_PATTERN}`;
        // Depth 2: allows depth-1 blocks inside.
        const FORMAT_OBJECT_DEPTH_2 = `${PREFIX_PATTERN}|${FORMAT_OBJECT_DEPTH_1}${SUFFIX_PATTERN}`;
        // Depth 3: allows depth-2 blocks inside.
        const FORMAT_OBJECT_DEPTH_3 = `${PREFIX_PATTERN}|${FORMAT_OBJECT_DEPTH_2}${SUFFIX_PATTERN}`;

        return {
          expression: {
            greedy: true,
            inside: {
              /* eslint-disable perfectionist/sort-objects -- Need to keep object order. */
              prefix: {
                alias: 'regex',
                pattern: /\$\{/
              },
              token: {
                alias: 'number',
                pattern: /^[^:}]+/
              },
              suffix: {
                alias: 'regex',
                pattern: /\}/
              }
              /* eslint-enable perfectionist/sort-objects -- Need to keep object order. */
            },
            pattern: /\$\{[^:}]+\}/
          },
          expressionWithFormat: {
            greedy: true,
            inside: {
              /* eslint-disable perfectionist/sort-objects -- Need to keep object order. */
              prefix: {
                alias: 'regex',
                pattern: /^\$\{/
              },
              token: {
                alias: 'number',
                pattern: /^[^:}]+/
              },
              formatDelimiter: {
                alias: 'regex',
                pattern: /^:/
              },
              format: {
                alias: 'language-javascript',
                inside: javascriptLanguage,
                pattern: new RegExp(`^${FORMAT_OBJECT_DEPTH_3}`)
              },
              suffix: {
                alias: 'regex',
                pattern: /\}$/
              }
              /* eslint-enable perfectionist/sort-objects -- Need to keep object order. */
            },
            pattern: new RegExp(String.raw`\$\{[^:}]+:${FORMAT_OBJECT_DEPTH_3}\}`)
          },
          important: {
            pattern: /^\./
          },
          operator: {
            alias: 'entity',
            pattern: /\//
          }
        };
      },
      language: TOKENIZED_STRING_LANGUAGE
    });
  }
}
