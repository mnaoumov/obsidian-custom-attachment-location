/**
 * @file
 *
 * Makes Obsidian's own *Files and links* page say who decides where new attachments go.
 *
 * While this plugin places attachments by its own template, Obsidian's *Default location for new attachments*
 * still shows the value the user stored there — a value that is not in effect. Two settings pages then disagree
 * about who decides. This replaces that row with one saying the plugin controls it, with a button to the
 * plugin's own setting. While the plugin follows Obsidian's location instead, Obsidian's value really is in
 * effect, so the page is left exactly as it is.
 *
 * This is the only patch here on a CORE SETTINGS TAB rather than an API, and the tab is Obsidian-internal with
 * no public contract. So it is written to fail closed: a missing tab, a missing method, no matching row, or a
 * throw anywhere in the rewrite all hand Obsidian its own definitions back untouched. A cosmetic honesty fix
 * must never be able to break Obsidian's settings.
 *
 * The rows are found by the config key their `render` writes, `attachmentFolderPath`, not by their names: the
 * names are localized, and the key is persisted in every vault's `app.json`, so it survives both translation
 * and minification.
 */

import type {
  App,
  SettingDefinitionItem,
  SettingDefinitionRender,
  SettingTab
} from 'obsidian';

import { registerAsyncEvent } from 'obsidian-dev-utils/obsidian/components/async-events-component';
import { MonkeyAroundComponent } from 'obsidian-dev-utils/obsidian/components/monkey-around-component';
import { t } from 'obsidian-dev-utils/obsidian/i18n/i18n';

import type { PluginSettingsComponent } from '../plugin-settings-component.ts';

const CORE_FILES_SETTING_TAB_ID = 'file';
const ATTACHMENT_FOLDER_PATH_CONFIG_KEY = 'attachmentFolderPath';

interface CoreFilesSettingTabPatchComponentConstructorParams {
  readonly app: App;
  readonly pluginId: string;
  readonly pluginSettingsComponent: PluginSettingsComponent;
}

export class CoreFilesSettingTabPatchComponent extends MonkeyAroundComponent {
  private readonly app: App;
  private coreFilesSettingTab: null | SettingTab = null;
  private isUnloading = false;
  private readonly pluginId: string;
  private readonly pluginSettingsComponent: PluginSettingsComponent;

  public constructor(params: CoreFilesSettingTabPatchComponentConstructorParams) {
    super();
    this.app = params.app;
    this.pluginId = params.pluginId;
    this.pluginSettingsComponent = params.pluginSettingsComponent;
  }

  public override onload(): void {
    const coreFilesSettingTab = this.app.setting.settingTabs.find((tab) => tab.id === CORE_FILES_SETTING_TAB_ID);
    // Obsidian-internal, and absent before the declarative settings API, so neither half is taken on trust.
    if (typeof coreFilesSettingTab?.getSettingDefinitions !== 'function') {
      return;
    }

    this.coreFilesSettingTab = coreFilesSettingTab;
    this.isUnloading = false;
    this.registerMethodPatch({
      $object: coreFilesSettingTab,
      methodName: 'getSettingDefinitions',
      patchHandler: ({ fallback }) => this.rewriteDefinitions(fallback())
    });

    /*
     * Obsidian renders the tab from the definitions it cached at its last `update()`, not from a fresh
     * `getSettingDefinitions()` call, so the relabel follows the setting only if every change re-runs it: a save
     * from the settings tab, and a reload of `data.json` written from outside (a sync client, say).
     */
    registerAsyncEvent(
      this,
      this.pluginSettingsComponent.on('loadSettings', () => {
        this.refreshCoreFilesSettingTab();
      })
    );
    registerAsyncEvent(
      this,
      this.pluginSettingsComponent.on('saveSettings', (newState, oldState) => {
        if (newState.effectiveValues.shouldFollowObsidianAttachmentLocation !== oldState.effectiveValues.shouldFollowObsidianAttachmentLocation) {
          this.refreshCoreFilesSettingTab();
        }
      })
    );

    this.refreshCoreFilesSettingTab();
  }

  public override onunload(): void {
    super.onunload();
    /*
     * Re-index Obsidian's own rows for search. The flag, rather than relying on the patch already being gone,
     * keeps this independent of the order in which a component runs its own and its registered teardown.
     */
    this.isUnloading = true;
    this.refreshCoreFilesSettingTab();
    this.coreFilesSettingTab = null;
  }

  private createControlledRow(originalDefinition: SettingDefinitionRender): SettingDefinitionRender {
    return {
      desc: t(($) => $.coreFilesSettingTab.controlledByPlugin),
      name: originalDefinition.name,
      render: (setting): void => {
        setting.addButton((button) => {
          button.setButtonText(t(($) => $.coreFilesSettingTab.openPluginSettings));
          button.onClick(() => {
            this.app.setting.openTabById(this.pluginId);
          });
        });
      }
    };
  }

  private refreshCoreFilesSettingTab(): void {
    try {
      this.coreFilesSettingTab?.update();
    } catch (error) {
      console.warn('Could not refresh Obsidian\'s Files and links settings tab', error);
    }
  }

  private rewriteDefinitions(definitions: SettingDefinitionItem[]): SettingDefinitionItem[] {
    if (this.isUnloading || this.pluginSettingsComponent.settings.shouldFollowObsidianAttachmentLocation) {
      return definitions;
    }

    try {
      const firstDefinition = definitions.find(isAttachmentFolderPathRow);
      if (!firstDefinition) {
        return definitions;
      }

      const rewritten: SettingDefinitionItem[] = [];
      for (const definition of definitions) {
        if (definition === firstDefinition) {
          rewritten.push(this.createControlledRow(firstDefinition));
        } else if (!isAttachmentFolderPathRow(definition)) {
          // The follow-up rows (the folder and the subfolder name) edit the same stored value, so they go too.
          rewritten.push(definition);
        }
      }

      return rewritten;
    } catch (error) {
      console.warn('Could not relabel Obsidian\'s attachment location setting; leaving it as it is', error);
      return definitions;
    }
  }
}

function isAttachmentFolderPathRow(definition: SettingDefinitionItem): definition is SettingDefinitionRender {
  const render = (definition as Partial<SettingDefinitionRender>).render;
  return typeof render === 'function' && render.toString().includes(ATTACHMENT_FOLDER_PATH_CONFIG_KEY);
}
