import { evalInObsidian } from 'obsidian-integration-testing';
import {
  describe,
  expect,
  it
} from 'vitest';

/*
 * End-to-end coverage for issue #68: the settings tab used to be one long scroll of nine groups.
 * `Core` now stays inline on the parent tab and the other eight groups are `SettingDefinitionPage`
 * sub-pages, so a section is reached by clicking its entry instead of scrolling to it.
 *
 * Only a real Obsidian can prove the three things that matter here, because all of them live in
 * Obsidian's own rendering of the definitions rather than in the definitions the plugin returns:
 *   - the parent tab renders the eight entries as navigable rows, not as ordinary settings;
 *   - clicking one pushes a titled sub-page holding exactly that section's rows, and the back
 *     button pops it again;
 *   - Obsidian's settings search still finds a row that now lives INSIDE a sub-page. That last one
 *     is the regression that would quietly make the split a downgrade: the rows would still be
 *     there, just unreachable for anyone who searches instead of navigating.
 */

const PLUGIN_ID = 'obsidian-custom-attachment-location';
const SETTLE_TIMEOUT_IN_MILLISECONDS = 600;
const SEARCH_SETTLE_TIMEOUT_IN_MILLISECONDS = 1200;

// No `Deletion` page since 12.0.0: every row it held belonged to the rename/delete handler this plugin
// Stopped registering, so the page emptied and was dropped rather than left as a bare label.
const EXPECTED_PAGE_NAMES = [
  'Move/renames',
  'Special characters',
  'Collected attachments',
  'Images',
  'Path',
  'Custom tokens',
  'Advanced'
];

const EXPECTED_IMAGES_PAGE_ROW_NAMES = [
  'Default image size',
  'Convert images to JPEG mode',
  'JPEG Quality',
  'Should preserve image metadata'
];

interface NavigableEntry {
  readonly description: string;
  readonly name: string;
}

interface ProbeResult {
  readonly navigableEntries: readonly NavigableEntry[];
  readonly pageStackDepthAfterBack: number;
  readonly pageStackDepthOnSubPage: number;
  readonly parentTabNames: readonly string[];
  readonly parentTabNamesAfterBack: readonly string[];
  readonly searchResultText: string;
  readonly subPageNames: readonly string[];
  readonly subPageTitle: string;
}

describe('Settings sub-pages (issue #68)', () => {
  it('navigates into a sub-page, back out again, and keeps sub-page rows searchable', async () => {
    const result = await evalInObsidian({
      async callback({ app, pluginId, searchSettleTimeoutInMilliseconds, settleTimeoutInMilliseconds }): Promise<ProbeResult> {
        const setting = app.setting;

        function text(el: Element | null): string {
          return (el?.textContent ?? '').trim();
        }

        function navigableEntryEls(): HTMLElement[] {
          return [...setting.modalEl.querySelectorAll<HTMLElement>(':scope .vertical-tab-content .setting-item.mod-navigable')];
        }

        function rowName(el: Element): string {
          return text(el.querySelector(':scope .setting-item-name'));
        }

        function tabRowNames(): string[] {
          return [...setting.modalEl.querySelectorAll(':scope .vertical-tab-content .setting-item-name')]
            .map((el) => text(el))
            .filter(Boolean);
        }

        setting.open();
        setting.openTabById(pluginId);
        await sleep(settleTimeoutInMilliseconds);

        const parentTabNames = tabRowNames();
        const navigableEntries = navigableEntryEls().map((entry) => ({
          description: text(entry.querySelector(':scope .setting-item-description')),
          name: rowName(entry)
        }));

        navigableEntryEls().find((entry) => rowName(entry) === 'Images')?.click();
        await sleep(settleTimeoutInMilliseconds);

        const subPageNames = tabRowNames();
        const subPageTitle = text(setting.titleTextEl);
        const pageStackDepthOnSubPage = setting.pageStack.length;

        setting.backButtonEl.click();
        await sleep(settleTimeoutInMilliseconds);

        const parentTabNamesAfterBack = tabRowNames();
        const pageStackDepthAfterBack = setting.pageStack.length;

        // `JPEG Quality` lives on the `Images` sub-page, so a search that finds it proves Obsidian
        // Indexes nested definitions rather than only the parent tab's own rows.
        setting.searchComponent.setValue('JPEG Quality');
        setting.searchComponent.onChanged();
        await sleep(searchSettleTimeoutInMilliseconds);

        const searchResultText = text(setting.searchResultsEl);

        /*
         * Close what this opened. Everything above is read off a LIVE settings dialog, and this suite
         * shares one Obsidian instance with every other one — leaving the dialog up leaks it for the
         * rest of the run. Measured: with this suite running immediately before
         * `link-update-progress`, that suite failed 3/3 (its rename produced no progress notice at
         * all), against 0/3 when run on its own. Closing here is what makes the two independent.
         */
        setting.close();
        await sleep(settleTimeoutInMilliseconds);

        return {
          navigableEntries,
          pageStackDepthAfterBack,
          pageStackDepthOnSubPage,
          parentTabNames,
          parentTabNamesAfterBack,
          searchResultText,
          subPageNames,
          subPageTitle
        };
      },
      input: {
        pluginId: PLUGIN_ID,
        searchSettleTimeoutInMilliseconds: SEARCH_SETTLE_TIMEOUT_IN_MILLISECONDS,
        settleTimeoutInMilliseconds: SETTLE_TIMEOUT_IN_MILLISECONDS
      }
    });

    expect(result.parentTabNames).toEqual([
      'Core',
      'Location for new attachments',
      'Generated attachment file name',
      ...EXPECTED_PAGE_NAMES
    ]);
    expect(result.navigableEntries.map((entry) => entry.name)).toEqual(EXPECTED_PAGE_NAMES);
    for (const entry of result.navigableEntries) {
      expect(entry.description, `Sub-page entry '${entry.name}' should carry a description`).not.toBe('');
    }

    expect(result.subPageTitle).toBe('Images');
    expect(result.pageStackDepthOnSubPage).toBe(1);
    expect(result.subPageNames).toEqual(EXPECTED_IMAGES_PAGE_ROW_NAMES);

    expect(result.pageStackDepthAfterBack).toBe(0);
    expect(result.parentTabNamesAfterBack).toEqual(result.parentTabNames);

    expect(result.searchResultText).toContain('JPEG Quality');
    expect(result.searchResultText).toContain('Images');
  });
});
