import { initI18N } from '@mnaoumov/obsidian-lib/i18n/i18n';
import {
  beforeAll,
  describe,
  expect,
  it
} from 'vitest';

import { translationsMap } from './locales/translations-map.ts';
import {
  codeNode,
  linkNode,
  translateFragment
} from './translate-fragment.ts';

function render(fragment: DocumentFragment): string {
  const div = createDiv();
  div.append(fragment);
  return div.innerHTML;
}

beforeAll(async () => {
  await initI18N(translationsMap);
});

describe('translateFragment', () => {
  it('should place a code node at its placeholder', () => {
    const html = render(translateFragment(($) => $.goToAttachmentFolder.doesNotExist, { folder: codeNode('assets/note') }));
    expect(html).toBe('The attachment folder <strong class="markdown-rendered code"><code>assets/note</code></strong> does not exist yet.');
  });

  it('should render each line break of the translation as a br', () => {
    const html = render(translateFragment(($) => $.pluginSettingsTab.specialCharacters.description, {}));
    expect(html).toBe('Special characters in attachment folder and file name to be replaced or removed.<br>Leave blank to preserve special characters.');
  });

  it('should place a link node and interpolate plain values from the options', () => {
    const html = render(translateFragment(
      ($) => $.notice.generatedAttachmentFileNameIsInvalid,
      { settingName: linkNode('https://example.com/', 'Generated attachment file name') },
      { path: 'a?b.png', validationMessage: 'Invalid character' }
    ));
    expect(html).toBe(
      'Generated attachment file name \'a?b.png\' is invalid.<br>Invalid character<br>Check your <a href="https://example.com/">Generated attachment file name</a> setting.'
    );
  });

  it('should keep an empty line as two consecutive breaks', () => {
    const html = render(translateFragment(($) => $.settingsMigrationModal.explanation, {}, { sourcePluginName: 'Source' }));
    expect(html).toContain('the way it did.<br><br>Each row');
  });

  it('should run a builder placeholder at its position', () => {
    const html = render(translateFragment(($) => $.attachmentCollector.confirm, {
      folders: (parent) => {
        parent.createEl('ul', { text: 'List' });
      }
    }));
    expect(html).toBe('Do you want to collect attachments for all notes in folders recursively?<br><ul>List</ul><br>This operation cannot be undone.');
  });
});
