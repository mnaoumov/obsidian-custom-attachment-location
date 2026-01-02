import { Component } from 'obsidian';
import { invokeAsyncSafely } from 'obsidian-dev-utils/Async';
import { loadPrism } from 'obsidian-typings/implementations';

export const TOKENIZED_STRING_LANGUAGE = 'custom-attachment-location-tokenized-string';

export class PrismComponent extends Component {
  public override onload(): void {
    super.onload();
    invokeAsyncSafely(this.initPrism.bind(this));
  }

  private async initPrism(): Promise<void> {
    const prism = await loadPrism();

    const javascriptLanguage = prism.languages['javascript'];

    if (!javascriptLanguage) {
      return;
    }

    const PREFIX_PATTERN = String.raw`\{(?:[^{}]|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'`;
    const SUFFIX_PATTERN = String.raw`)*\}`;

    const FORMAT_OBJECT_DEPTH_1 = `${PREFIX_PATTERN}${SUFFIX_PATTERN}`;
    // Depth 2: allows depth-1 blocks inside.
    const FORMAT_OBJECT_DEPTH_2 = `${PREFIX_PATTERN}|${FORMAT_OBJECT_DEPTH_1}${SUFFIX_PATTERN}`;
    // Depth 3: allows depth-2 blocks inside.
    const FORMAT_OBJECT_DEPTH_3 = `${PREFIX_PATTERN}|${FORMAT_OBJECT_DEPTH_2}${SUFFIX_PATTERN}`;

    prism.languages[TOKENIZED_STRING_LANGUAGE] = {
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

    this.register(() => {
      // eslint-disable-next-line @typescript-eslint/no-dynamic-delete -- Need to delete language.
      delete prism.languages[TOKENIZED_STRING_LANGUAGE];
    });
  }
}
