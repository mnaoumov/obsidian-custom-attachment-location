import { evalInObsidian } from 'obsidian-integration-testing';
import {
  describe,
  expect,
  it
} from 'vitest';

/*
 * End-to-end coverage for issue #86: with `Rename attachments created by other plugins` set to a list mode, the
 * `Plugins` picker rendered as a one-row dropdown that never opened, so no plugin could be chosen.
 *
 * The picker is a `<select multiple>`, which has no popup: it is usable only when it is tall enough to show its
 * options as a list. Its height comes from CSS, and whether a rule matches is decided by Obsidian's real DOM, so
 * only a real Obsidian can tell a working picker from a collapsed one.
 */

const PLUGIN_ID = 'obsidian-custom-attachment-location';
const POLL_INTERVAL_IN_MILLISECONDS = 100;
const SETTLE_TIMEOUT_IN_MILLISECONDS = 600;
const VISIBLE_TIMEOUT_IN_MILLISECONDS = 5000;

interface ProbeResult {
  readonly clientHeight: number;
  readonly computedHeight: string;
  readonly found: boolean;
  readonly optionCount: number;
  readonly optionHeight: number;
}

describe('Plugins picker (issue #86)', () => {
  it('renders as an expanded list, not a one-row dropdown', async () => {
    const result = await evalInObsidian({
      async callback({ app, pluginId, pollIntervalInMilliseconds, settleTimeoutInMilliseconds, visibleTimeoutInMilliseconds }): Promise<ProbeResult> {
        const setting = app.setting;

        function text(el: Element | null): string {
          return (el?.textContent ?? '').trim();
        }

        function rowByName(name: string): HTMLElement | undefined {
          return [...setting.modalEl.querySelectorAll<HTMLElement>(':scope .vertical-tab-content .setting-item')]
            .find((row) => text(row.querySelector(':scope .setting-item-name')) === name);
        }

        setting.open();
        setting.openTabById(pluginId);
        await sleep(settleTimeoutInMilliseconds);

        rowByName('Move/renames')?.click();
        await sleep(settleTimeoutInMilliseconds);

        const modeSelect = rowByName('Rename attachments created by other plugins')?.querySelector('select');
        const originalMode = modeSelect?.value ?? '';
        if (modeSelect) {
          modeSelect.value = 'Only listed plugins';
          modeSelect.dispatchEvent(new Event('change'));
        }

        // The row appears through the settings tab's `visible` predicate once the mode changes; wait for it to be laid out.
        let selectEl: HTMLSelectElement | null = null;
        const deadline = Date.now() + visibleTimeoutInMilliseconds;
        while (Date.now() < deadline) {
          selectEl = rowByName('Plugins')?.querySelector<HTMLSelectElement>('select[multiple]') ?? null;
          if (selectEl && selectEl.clientHeight > 0) {
            break;
          }
          await sleep(pollIntervalInMilliseconds);
        }

        const probe: ProbeResult = {
          clientHeight: selectEl?.clientHeight ?? 0,
          computedHeight: selectEl ? getComputedStyle(selectEl).height : '',
          found: selectEl !== null,
          optionCount: selectEl?.options.length ?? 0,
          optionHeight: selectEl?.options[0]?.getBoundingClientRect().height ?? 0
        };

        // One Obsidian instance serves every suite: put the mode back and close the dialog this opened.
        if (modeSelect) {
          modeSelect.value = originalMode;
          modeSelect.dispatchEvent(new Event('change'));
        }
        setting.close();
        await sleep(settleTimeoutInMilliseconds);

        return probe;
      },
      input: {
        pluginId: PLUGIN_ID,
        pollIntervalInMilliseconds: POLL_INTERVAL_IN_MILLISECONDS,
        settleTimeoutInMilliseconds: SETTLE_TIMEOUT_IN_MILLISECONDS,
        visibleTimeoutInMilliseconds: VISIBLE_TIMEOUT_IN_MILLISECONDS
      }
    });

    expect(result.found, 'the Plugins row should hold a multiple select once a list mode is chosen').toBe(true);
    expect(result.optionCount, 'the vault seeds Advanced Rename and Delete Handler, so there is a plugin to list').toBeGreaterThan(0);
    expect(result.optionHeight, 'the picker should be laid out, not hidden').toBeGreaterThan(0);
    // One row tall is the defect: Obsidian's `.dropdown` height, with no popup behind it.
    expect(result.clientHeight, `the picker should show several rows, got ${result.computedHeight}`).toBeGreaterThanOrEqual(2 * result.optionHeight);
  });
});
