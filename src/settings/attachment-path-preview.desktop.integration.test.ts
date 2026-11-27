import { evalInObsidian } from 'obsidian-integration-testing';
import {
  describe,
  expect,
  it
} from 'vitest';

import { findPluginSettingsComponent } from '../../scripts/helpers/plugin-settings-component-finder.ts';

/*
 * The `Preview` row under the core templates shows where a new attachment would be saved, and recomputes as the user
 * types. Only the real settings tab proves it: the row is rendered by Obsidian from the declarative definitions, the
 * user's keystrokes reach the template through the library binding, and the preview is resolved by the plugin's own
 * resolver. Typing `{{prompt}}` must show the token and open nothing, since the preview runs on every keystroke.
 */

const PLUGIN_ID = 'obsidian-custom-attachment-location';
const PREVIEW_ROW_NAME = 'Preview';
const TEMPLATE_ROW_NAME = 'Generated attachment file name';

interface ProbeResult {
  readonly error: string;
  readonly initialPreview: readonly string[];
  readonly modalCountAfterPrompt: number;
  readonly modalCountBefore: number;
  readonly previewAfterPrompt: readonly string[];
  readonly previewAfterTyping: readonly string[];
  readonly settingsFound: boolean;
}

describe('Template preview in settings', () => {
  it('shows where a new attachment would go, and follows the template as it is typed', async () => {
    const result = await evalInObsidian({
      async callback({ app, findPluginSettingsComponent: findSettingsComponent, lib: { clickMouse, openSettingsTab, pressKey, waitUntil }, pluginId, previewRowName, templateRowName }): Promise<ProbeResult> {
        interface Settings {
          // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors.
          attachmentFolderPath: string;
          // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors.
          generatedAttachmentFileName: string;
          // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors.
          shouldFollowObsidianAttachmentLocation: boolean;
        }
        function isSettings(value: unknown): value is Settings {
          return typeof value === 'object' && value !== null && typeof (value as Record<string, unknown>)['generatedAttachmentFileName'] === 'string';
        }
        const empty: ProbeResult = {
          error: '',
          initialPreview: [],
          modalCountAfterPrompt: 0,
          modalCountBefore: 0,
          previewAfterPrompt: [],
          previewAfterTyping: [],
          settingsFound: false
        };
        const settingsComponent = findSettingsComponent(app.plugins.getPlugin(pluginId), isSettings);
        if (!settingsComponent) {
          return empty;
        }

        const prior = { ...settingsComponent.settings };

        function findRow(rowName: string): HTMLElement {
          const row = [...app.setting.modalEl.querySelectorAll<HTMLElement>(':scope .vertical-tab-content .setting-item')]
            .find((el) => el.querySelector(':scope .setting-item-name')?.textContent.trim() === rowName);
          if (!row) {
            throw new Error(`The ${rowName} row is not rendered.`);
          }
          return row;
        }

        function readPreview(): string[] {
          return [...findRow(previewRowName).querySelectorAll(':scope .setting-item-description code')].map((code) => code.textContent);
        }

        function countModals(): number {
          return document.querySelectorAll('.modal-container').length;
        }

        async function retypeTemplate(text: string): Promise<void> {
          const input = findRow(templateRowName).querySelector<HTMLElement>(':scope textarea, :scope input');
          if (!input) {
            throw new Error(`The ${templateRowName} row has no text box.`);
          }
          const rect = input.getBoundingClientRect();
          await clickMouse({ x: rect.left + rect.width / 2, y: rect.top + rect.height / 2 });
          await pressKey({ key: 'a', modifiers: ['Mod'] });
          await pressKey({ key: 'Backspace' });
          for (const character of text) {
            await pressKey({ key: character });
          }
          await waitUntil({
            message: `the template to read ${text}`,
            predicate: () => settingsComponent?.settings.generatedAttachmentFileName === text
          });
        }

        try {
          await settingsComponent.editAndSave((settings) => {
            settings.shouldFollowObsidianAttachmentLocation = false;
            settings.attachmentFolderPath = 'preview-assets';
            settings.generatedAttachmentFileName = 'fixed';
          });
          await openSettingsTab({ tabId: pluginId });
          await waitUntil({
            message: 'the first preview to be shown',
            predicate: () => readPreview().at(-1) === 'preview-assets/fixed.png'
          });
          const initialPreview = readPreview();

          await retypeTemplate('{{noteFileName}}-shot');
          await waitUntil({
            message: 'the preview to follow the typed template',
            predicate: () => readPreview().at(-1)?.endsWith('-shot.png') === true
          });
          const previewAfterTyping = readPreview();

          const modalCountBefore = countModals();
          await retypeTemplate('{{prompt}}');
          await waitUntil({
            message: 'the preview to show the prompt token',
            predicate: () => readPreview().at(-1) === 'preview-assets/{{prompt}}.png'
          });
          const previewAfterPrompt = readPreview();
          const modalCountAfterPrompt = countModals();

          return { error: '', initialPreview, modalCountAfterPrompt, modalCountBefore, previewAfterPrompt, previewAfterTyping, settingsFound: true };
        } catch (error) {
          return { ...empty, error: String(error), settingsFound: true };
        } finally {
          app.setting.close();
          await settingsComponent.editAndSave((settings) => {
            settings.attachmentFolderPath = prior.attachmentFolderPath;
            settings.generatedAttachmentFileName = prior.generatedAttachmentFileName;
            settings.shouldFollowObsidianAttachmentLocation = prior.shouldFollowObsidianAttachmentLocation;
          });
        }
      },
      input: { findPluginSettingsComponent, pluginId: PLUGIN_ID, previewRowName: PREVIEW_ROW_NAME, templateRowName: TEMPLATE_ROW_NAME }
    });

    expect(result.settingsFound).toBe(true);
    expect(result.error).toBe('');
    // The sample attachment, the note it is previewed for, and the path.
    expect(result.initialPreview).toHaveLength(3);
    expect(result.initialPreview[0]).toBe('Pasted image.png');
    const notePath = result.initialPreview[1] ?? '';
    const noteBaseName = notePath.slice(notePath.lastIndexOf('/') + 1).replace(/\.md$/, '');
    expect(result.previewAfterTyping.at(-1)).toBe(`preview-assets/${noteBaseName}-shot.png`);
    expect(result.previewAfterPrompt.at(-1)).toBe('preview-assets/{{prompt}}.png');
    expect(result.modalCountAfterPrompt).toBe(result.modalCountBefore);
  });
});
