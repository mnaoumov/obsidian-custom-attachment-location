import type { PrismModule } from '@obsidian-typings/obsidian-public-latest';

import { evalInObsidian } from 'obsidian-integration-testing';
import {
  describe,
  expect,
  it
} from 'vitest';

// Declared here rather than imported from `tokenized-string-language-component.ts`: this file runs in Node,
// And that module pulls in `obsidian`, which only resolves inside the app.
const TOKENIZED_STRING_LANGUAGE = 'custom-attachment-location-tokenized-string';

describe('tokenized-string language', () => {
  // eslint-disable-next-line no-template-curly-in-string -- Intentional plugin token, not a JS template literal.
  it('highlights the ${token:format} placeholders of a tokenized string through real Prism', async () => {
    const result = await evalInObsidian({
      async callback({ language, lib: { waitUntil }, obsidianModule }) {
        // `obsidian`'s own `loadPrism()` is typed as returning `unknown`.
        const prism = await obsidianModule.loadPrism() as PrismModule;

        await waitUntil({
          message: `Prism language "${language}" was not registered`,
          predicate: () => prism.languages[language] !== undefined
        });

        const grammar = prism.languages[language];
        if (!grammar) {
          throw new Error(`Prism language "${language}" is missing.`);
        }

        /* eslint-disable no-template-curly-in-string -- Intentional plugin tokens, not JS template literals. */
        return {
          nestedJavaScriptHtml: prism.highlight('${date:{ format: "YYYY" }}', grammar, language),
          plainHtml: prism.highlight('./${noteFileName}/${date:YYYY-MM-DD}', grammar, language)
        };
        /* eslint-enable no-template-curly-in-string -- Intentional plugin tokens, not JS template literals. */
      },
      input: { language: TOKENIZED_STRING_LANGUAGE }
    });

    // The settings tab's code-highlighter fields render exactly this markup, so this asserts what the
    // User sees: each part of the tokenized string carries its own token class.
    expect(result.plainHtml).toContain('class="token important"');
    expect(result.plainHtml).toContain('class="token operator entity"');
    expect(result.plainHtml).toContain('class="token prefix regex"');
    expect(result.plainHtml).toContain('class="token token number"');
    expect(result.plainHtml).toContain('class="token suffix regex"');

    // The `${token:{...}}` format block nests the real `javascript` grammar, which is the whole reason the
    // Grammar is built through the factory form. A nested JavaScript string proves the nesting is live.
    expect(result.nestedJavaScriptHtml).toContain('class="token formatDelimiter regex"');
    expect(result.nestedJavaScriptHtml).toContain('language-javascript');
    expect(result.nestedJavaScriptHtml).toContain('class="token string"');
  });
});
