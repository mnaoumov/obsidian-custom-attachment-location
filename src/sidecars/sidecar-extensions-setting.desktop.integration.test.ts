import { evalInObsidian } from 'obsidian-integration-testing';
import {
  describe,
  expect,
  it
} from 'vitest';

import { findPluginSettingsComponent } from '../../scripts/helpers/plugin-settings-component-finder.ts';

/*
 * The `Sidecar extensions` description says that clearing the list disables pairing. Until this suite, clearing
 * the box put the defaults straight back, because the library binding treats an empty text box as "use the
 * default". Only the real settings tab proves the fix: the user's keystrokes clear the box, the setting stays empty
 * after the tab is closed and reopened, and the row's reset button brings the default extensions back.
 */

const PLUGIN_ID = 'obsidian-custom-attachment-location';
const ROW_NAME = 'Sidecar extensions';
// The default list from PluginSettings. A Node-side import of it would load obsidian, which only the renderer has.
const DEFAULT_SIDECAR_EXTENSIONS = ['p7s', 'sig', 'asc', 'srt', 'vtt'];

interface ProbeResult {
  readonly error: string;
  readonly extensionsAfterClear: readonly string[];
  readonly extensionsAfterReset: readonly string[];
  readonly initialExtensions: readonly string[];
  readonly settingsFound: boolean;
  readonly textAfterReopen: string;
  readonly textAfterReset: string;
}

describe('Sidecar extensions setting', () => {
  it('keeps a cleared list empty, and restores the defaults from the reset button', async () => {
    const result = await evalInObsidian({
      async callback({ app, findPluginSettingsComponent: findSettingsComponent, lib: { clickMouse, openSettingsTab, pressKey, waitUntil }, pluginId, rowName }): Promise<ProbeResult> {
        interface Settings {
          // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors.
          sidecarExtensions: string[];
        }
        function isSettings(value: unknown): value is Settings {
          return typeof value === 'object' && value !== null && Array.isArray((value as Record<string, unknown>)['sidecarExtensions']);
        }
        const empty: ProbeResult = {
          error: '',
          extensionsAfterClear: [],
          extensionsAfterReset: [],
          initialExtensions: [],
          settingsFound: false,
          textAfterReopen: '',
          textAfterReset: ''
        };
        const settingsComponent = findSettingsComponent(app.plugins.getPlugin(pluginId), isSettings);
        if (!settingsComponent) {
          return empty;
        }

        const prior = [...settingsComponent.settings.sidecarExtensions];

        function findRow(): HTMLElement {
          const row = [...app.setting.modalEl.querySelectorAll<HTMLElement>(':scope .vertical-tab-content .setting-item')]
            .find((el) => el.querySelector(':scope .setting-item-name')?.textContent.trim() === rowName);
          if (!row) {
            throw new Error(`The ${rowName} row is not rendered.`);
          }
          return row;
        }

        function findTextArea(): HTMLTextAreaElement {
          const textArea = findRow().querySelector<HTMLTextAreaElement>(':scope textarea');
          if (!textArea) {
            throw new Error(`The ${rowName} row has no text box.`);
          }
          return textArea;
        }

        async function clickCenter(el: HTMLElement): Promise<void> {
          const rect = el.getBoundingClientRect();
          await clickMouse({ x: rect.left + rect.width / 2, y: rect.top + rect.height / 2 });
        }

        try {
          await openSettingsTab({ tabId: pluginId });
          const initialExtensions = findTextArea().value.split('\n');

          // The user's own keystrokes: focus the box, select everything, delete it.
          await clickCenter(findTextArea());
          await pressKey({ key: 'a', modifiers: ['Mod'] });
          await pressKey({ key: 'Backspace' });
          await waitUntil({
            message: 'the cleared sidecar extension list to be saved',
            predicate: () => settingsComponent.settings.sidecarExtensions.length === 0
          });
          const extensionsAfterClear = [...settingsComponent.settings.sidecarExtensions];

          // Leaving the box used to snap it back to the defaults, so close the tab and look again.
          app.setting.close();
          await openSettingsTab({ tabId: pluginId });
          const textAfterReopen = findTextArea().value;

          const resetButton = findRow().querySelector<HTMLElement>(':scope .extra-setting-button');
          if (!resetButton) {
            throw new Error(`The ${rowName} row has no reset button.`);
          }
          await clickCenter(resetButton);
          await waitUntil({
            message: 'the default sidecar extensions to be restored',
            predicate: () => settingsComponent.settings.sidecarExtensions.length > 0
          });
          const extensionsAfterReset = [...settingsComponent.settings.sidecarExtensions];
          await waitUntil({
            message: 'the restored extensions to be shown in the box',
            predicate: () => findTextArea().value !== ''
          });
          const textAfterReset = findTextArea().value;

          return { error: '', extensionsAfterClear, extensionsAfterReset, initialExtensions, settingsFound: true, textAfterReopen, textAfterReset };
        } catch (error) {
          return { ...empty, error: String(error), settingsFound: true };
        } finally {
          app.setting.close();
          await settingsComponent.editAndSave((settings) => {
            settings.sidecarExtensions = prior;
          });
        }
      },
      input: { findPluginSettingsComponent, pluginId: PLUGIN_ID, rowName: ROW_NAME }
    });

    expect(result.settingsFound).toBe(true);
    expect(result.error).toBe('');
    expect(result.initialExtensions.length).toBeGreaterThan(0);
    expect(result.extensionsAfterClear).toStrictEqual([]);
    expect(result.textAfterReopen).toBe('');
    expect(result.extensionsAfterReset).toStrictEqual(DEFAULT_SIDECAR_EXTENSIONS);
    expect(result.textAfterReset).toBe(DEFAULT_SIDECAR_EXTENSIONS.join('\n'));
  });
});
