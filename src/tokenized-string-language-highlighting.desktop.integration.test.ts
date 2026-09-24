import type { PrismModule } from '@obsidian-typings/obsidian-public-latest';

import { evalInObsidian } from 'obsidian-integration-testing';
import {
  describe,
  expect,
  it
} from 'vitest';

// Declared here rather than imported from `tokenized-string-language.ts`: this file runs in Node,
// And that module pulls in `obsidian`, which only resolves inside the app.
const TOKENIZED_STRING_LANGUAGE = 'custom-attachment-location-tokenized-string';

describe('tokenized-string language', () => {
  it('highlights the {{token:format}} placeholders of a tokenized string through real Prism', async () => {
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

        return {
          nestedJavaScriptHtml: prism.highlight('{{date:{ format: "YYYY" }}}', grammar, language),
          nestedTemplateHtml: prism.highlight('{{prompt:{ defaultValueTemplate: "{{originalAttachmentFileName}}" }}}', grammar, language),
          plainHtml: prism.highlight('./{{noteFileName}}/{{date:YYYY-MM-DD}}', grammar, language)
        };
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

    // The `{{token:{...}}}` format block nests the real `javascript` grammar, which is the whole reason the
    // Grammar is built through the factory form. A nested JavaScript string proves the nesting is live.
    expect(result.nestedJavaScriptHtml).toContain('class="token formatDelimiter regex"');
    expect(result.nestedJavaScriptHtml).toContain('language-javascript');
    expect(result.nestedJavaScriptHtml).toContain('class="token string"');
    // Only the delimiter after the token name is one; the `:` inside the object belongs to the JavaScript.
    expect(result.nestedJavaScriptHtml.match(/class="token formatDelimiter regex"/g)).toHaveLength(1);

    // The scalar shorthand is core's own `{{date:YYYY-MM-DD}}`, a plain string rather than JavaScript.
    expect(result.plainHtml).toContain('class="token scalarFormat string"');
    expect(result.plainHtml).not.toContain('language-javascript');

    // A `{{...}}` template nested in a format object stays inside that object's JavaScript string, rather than
    // Being taken for a second placeholder: the whole token is ONE `expressionWithFormat`.
    expect(result.nestedTemplateHtml.match(/class="token expressionWithFormat"/g)).toHaveLength(1);
    expect(result.nestedTemplateHtml).toContain('class="token string"');
    expect(result.nestedTemplateHtml.match(/class="token prefix regex"/g)).toHaveLength(1);
  });
});
