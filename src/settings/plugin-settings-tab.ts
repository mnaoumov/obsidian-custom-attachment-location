import type { PluginGateComponent } from '@mnaoumov/obsidian-lib/components/plugin-gate-component';
import type {
  BindOptionsExtended,
  PluginSettingsTabBaseConstructorParams
} from '@mnaoumov/obsidian-lib/plugin/plugin-settings-tab';
import type {
  ButtonComponent,
  SettingDefinitionItem,
  SettingDefinitionPage,
  SettingDefinitionRender,
  TextComponent
} from 'obsidian';
import type { ConditionalKeys } from 'type-fest';

import {
  appendCodeBlock,
  asCodeBlock,
  createFragmentWithCodeBlocks
} from '@mnaoumov/obsidian-lib/html-element';
import { t } from '@mnaoumov/obsidian-lib/i18n/i18n';
import { alert } from '@mnaoumov/obsidian-lib/modals/alert';
import { confirm } from '@mnaoumov/obsidian-lib/modals/confirm';
import { addPluginCssClasses } from '@mnaoumov/obsidian-lib/plugin/plugin-context';
import { PluginSettingsTabBase } from '@mnaoumov/obsidian-lib/plugin/plugin-settings-tab';
import {
  convertAsyncToSync,
  invokeAsyncSafely
} from '@mnaoumov/typescript-lib/async';
import { ensureNonNullable } from '@mnaoumov/typescript-lib/type-guards';
import {
  debounce,
  normalizePath,
  Platform
} from 'obsidian';

import type { TranslationNode } from '../i18n/translate-fragment.ts';
import type { OriginalAttachmentNamesComponent } from '../original-attachment-names/original-attachment-names-component.ts';
import type { PluginSettingsComponent } from './plugin-settings-component.ts';

import {
  CUSTOM_TOKENS_DOCUMENTATION_URL,
  TOKEN_REFERENCE_DOCUMENTATION_URL
} from '../documentation-links.ts';
import {
  codeNode,
  linkNode,
  translateFragment
} from '../i18n/translate-fragment.ts';
import {
  getObsidianSyncStatus,
  ObsidianSyncState
} from '../original-attachment-names/obsidian-sync-status.ts';
import { getOriginalNameTransportRoot } from '../original-attachment-names/original-attachment-names-component.ts';
import {
  doesAnySettingReadOriginalAttachmentFileName,
  getOriginalNameSyncAdvice,
  OriginalNameSyncAdvice
} from '../original-attachment-names/original-name-sync-advice.ts';
import {
  isPluginOwnedDataFolder,
  PLUGIN_DATA_SUBFOLDER_NAME
} from '../original-attachment-names/plugin-data-folder.ts';
import { Substitutions } from '../tokens/substitutions.ts';
import { TOKENIZED_STRING_LANGUAGE } from '../tokens/tokenized-string-language.ts';
import {
  ATTACHMENT_OPERATION_TEMPLATE_KEYS,
  AttachmentOperation
} from './attachment-operation.ts';
import {
  AttachmentRenameMode,
  CollectAttachmentUsedByMultipleNotesMode,
  ConvertImagesToJpegMode,
  DefaultImageSizeDimension,
  MoveAttachmentToProperFolderUsedByMultipleNotesMode,
  OrphanAttachmentScanMode,
  PluginSettings,
  RenameAttachmentsCreatedByOtherPluginsMode,
  SAMPLE_CUSTOM_TOKENS
} from './plugin-settings.ts';

const VISIBLE_SPACE_CHARACTER = '␣';
const JPEG_QUALITY_PRECISION = 2;
const REGISTER_CUSTOM_TOKENS_DEBOUNCE_IN_MILLISECONDS = 2000;

/**
 * A file name to ask Obsidian Sync's filter about. Only its extension matters: the history is stored as JSON.
 */
const SYNC_PROBE_FILE_NAME = 'history.json';

const bindOptionsWithTrim: BindOptionsExtended<PluginSettings, string, ConditionalKeys<PluginSettings, string>> = {
  componentToPluginSettingsValueConverter(uiValue: string): string {
    return normalizePath(uiValue.trimEnd());
  },
  pluginSettingsToComponentValueConverter(pluginSettingsValue: string): string {
    return pluginSettingsValue.trimEnd();
  },
  shouldResetSettingWhenComponentIsEmpty: true,
  shouldShowPlaceholderForDefaultValues: false
};

interface PluginSettingsTabConstructorParams extends PluginSettingsTabBaseConstructorParams<PluginSettings> {
  readonly getOriginalAttachmentNamesComponent?: (this: void) => OriginalAttachmentNamesComponent;
  /**
   * Reaches the plugin's gate, LAZILY.
   *
   * A function rather than the component itself, because there is no component to hand over yet when this
   * tab is built: the base assigns `pluginGateComponent` only after the gate has loaded, and the gate loads
   * the feature surface — `onloadImpl`, where this tab is constructed — as it loads. Reading it eagerly
   * therefore throws. By the time a row renders, the assignment has long since happened.
   *
   * @returns The plugin gate component.
   */
  readonly getPluginGateComponent: (this: void) => PluginGateComponent;
  readonly pluginSettingsComponent: PluginSettingsComponent;
}

interface PluginSettingsTabGetAttachmentOperationPageParams {
  readonly description: string;
  /**
   * State beyond the operation's templates that also departs from the default.
   */
  readonly isCustomized?: () => boolean;
  readonly items: SettingDefinitionItem[];
  readonly name: string;
  readonly operation: AttachmentOperation;
}

interface PluginSettingsTabGetNewAttachmentOperationTemplateItemParams {
  readonly description: string;
  readonly hint: string;
  readonly name: string;
  readonly propertyName: ConditionalKeys<PluginSettings, string>;
}

interface PluginSettingsTabGetNewAttachmentOperationTemplateItemsParams {
  readonly description: string;
  readonly fileName: string;
  readonly folderPath: string;
  readonly operation: AttachmentOperation;
}

export class PluginSettingsTab extends PluginSettingsTabBase<PluginSettings> {
  private readonly getOriginalAttachmentNamesComponent: ((this: void) => OriginalAttachmentNamesComponent) | null;
  private readonly getPluginGateComponent: (this: void) => PluginGateComponent;
  // Kept so this plugin can leave ITSELF out of the plugin picker; the base class does not expose `plugin`.
  private readonly ownPluginId: string;
  private readonly pluginSettingsComponent2: PluginSettingsComponent;

  public constructor(params: PluginSettingsTabConstructorParams) {
    super(params);
    this.getPluginGateComponent = params.getPluginGateComponent;
    this.getOriginalAttachmentNamesComponent = params.getOriginalAttachmentNamesComponent ?? null;
    this.ownPluginId = params.plugin.manifest.id;
    this.pluginSettingsComponent2 = params.pluginSettingsComponent;
  }

  public override hide(): void {
    super.hide();
    this.pluginSettingsComponent2.shouldDebounceCustomTokensValidation = false;
    // Closing cancels a pending debounced registration, so tokens typed just before closing are registered here.
    invokeAsyncSafely(async () => {
      await this.pluginSettingsComponent2.revalidate();
    });
  }

  protected override getSettingDefinitionItems(): SettingDefinitionItem[] {
    return [
      // The overlap banner has to travel as a ROW: Obsidian renders the declarative definitions and never
      // calls `display()` once `getSettingDefinitions()` is non-empty, so there is no container to write into
      // otherwise. The row body is emptied first, leaving the Setting element as a bare host for the banner.
      // The row exists only while a warning conflict holds, since the library renders nothing otherwise and an
      // empty row is still a divider and a block of padding.
      //
      // There is no row for `Advanced Rename and Delete Handler`: it is a declared dependency, so while it is
      // missing this tab is never registered at all and the library's own blocked tab explains what to install.
      this.settingEx({
        name: '',
        render: (setting) => {
          setting.settingEl.empty();
          this.getPluginGateComponent().renderConflictWarningBanner(setting.settingEl);
        },
        searchable: false,
        visible: () => this.getPluginGateComponent().hasActiveWarningConflicts()
      }),
      this.settingGroupEx({
        heading: t(($) => $.pluginSettingsTab.groups.core),
        items: this.getCoreItems()
      }),
      {
        desc: createFragmentWithCodeBlocks(t(($) => $.originalAttachmentNames.storage.description, {
          originalAttachmentFileName: asTokenCodeBlock('originalAttachmentFileName')
        })),
        items: this.getStorageItems(),
        name: t(($) => $.originalAttachmentNames.storage.title),
        type: 'page'
      },
      {
        desc: t(($) => $.pluginSettingsTab.pages.moveRenames.description),
        items: this.getMoveRenamesItems(),
        name: t(($) => $.pluginSettingsTab.groups.moveRenames),
        type: 'page'
      },
      {
        desc: t(($) => $.pluginSettingsTab.pages.attachmentOperations.description),
        items: this.getAttachmentOperationPages(),
        name: t(($) => $.pluginSettingsTab.groups.attachmentOperations),
        type: 'page'
      },
      {
        desc: t(($) => $.pluginSettingsTab.pages.specialCharacters.description),
        items: this.getSpecialCharactersItems(),
        name: t(($) => $.pluginSettingsTab.groups.specialCharacters),
        type: 'page'
      },
      {
        desc: t(($) => $.pluginSettingsTab.pages.collectedAttachments.description),
        items: this.getCollectedAttachmentsItems(),
        name: t(($) => $.pluginSettingsTab.groups.collectedAttachments),
        type: 'page'
      },
      {
        desc: t(($) => $.pluginSettingsTab.pages.images.description),
        items: this.getImagesItems(),
        name: t(($) => $.pluginSettingsTab.groups.images),
        type: 'page'
      },
      {
        desc: t(($) => $.pluginSettingsTab.pages.path.description),
        items: this.getPathItems(),
        name: t(($) => $.pluginSettingsTab.groups.path),
        type: 'page'
      },
      {
        desc: t(($) => $.pluginSettingsTab.pages.customTokens.description),
        items: this.getCustomTokensItems(),
        name: t(($) => $.pluginSettingsTab.groups.customTokens),
        type: 'page'
      },
      {
        desc: t(($) => $.pluginSettingsTab.pages.advanced.description),
        items: this.getAdvancedItems(),
        name: t(($) => $.pluginSettingsTab.groups.advanced),
        type: 'page'
      }
    ];
  }

  private getAdvancedItems(): SettingDefinitionRender[] {
    return [
      this.settingEx({
        desc: createFragmentWithCodeBlocks(t(($) => $.pluginSettingsTab.insertedLinkText.description, {
          attachmentFileName: asTokenCodeBlock('attachmentFileName'),
          originalAttachmentFileName: asTokenCodeBlock('originalAttachmentFileName')
        })),
        name: t(($) => $.pluginSettingsTab.insertedLinkText.name),
        render: (setting) => {
          setting.addCodeHighlighter((codeHighlighter) => {
            codeHighlighter.setLanguage(TOKENIZED_STRING_LANGUAGE);
            codeHighlighter.inputEl.addClass('tokenized-string-setting-control');
            this.bind({
              propertyName: 'insertedLinkText',
              shouldShowPlaceholderForDefaultValues: false,
              valueComponent: codeHighlighter
            });
          });
        }
      }),
      this.settingEx({
        desc: translateFragment(($) => $.pluginSettingsTab.markdownUrlFormat.description, { tokens: tokensLinkNode() }),
        name: t(($) => $.pluginSettingsTab.markdownUrlFormat.name),
        render: (setting) => {
          setting.addCodeHighlighter((codeHighlighter) => {
            codeHighlighter.setLanguage(TOKENIZED_STRING_LANGUAGE);
            codeHighlighter.inputEl.addClass('tokenized-string-setting-control');
            this.bind({
              propertyName: 'markdownUrlFormat',
              valueComponent: codeHighlighter,
              ...bindOptionsWithTrim
            });
          });
        }
      }),
      this.settingEx({
        desc: t(($) => $.pluginSettingsTab.shouldCommitBulkOperations.description),
        name: t(($) => $.pluginSettingsTab.shouldCommitBulkOperations.name),
        render: (setting) => {
          setting.addToggle((toggle) => {
            this.bind({
              propertyName: 'shouldCommitBulkOperations',
              valueComponent: toggle
            });
          });
        },
        // The commits are made by the system git, which only the desktop app can run.
        visible: () => Platform.isDesktopApp
      }),
      this.settingEx({
        desc: translateFragment(($) => $.pluginSettingsTab.timeoutInSeconds.description, { zero: codeNode('0') }),
        name: t(($) => $.pluginSettingsTab.timeoutInSeconds.name),
        render: (setting) => {
          setting.addNumber(($number) => {
            $number.setMin(0);
            this.bind({
              propertyName: 'timeoutInSeconds',
              valueComponent: $number
            });
          });
        }
      })
    ];
  }

  private getAttachmentOperationPage(params: PluginSettingsTabGetAttachmentOperationPageParams): SettingDefinitionPage {
    return {
      desc: params.description,
      // Read on every render of the parent page, so returning from the operation's page shows the value just edited.
      displayValue: (): string => {
        const settings = this.pluginSettingsComponent.settings;
        const isCustomized = settings.getOperationFileName(params.operation) !== ''
          || settings.getOperationFolderPath(params.operation) !== ''
          || params.isCustomized?.() === true;
        return isCustomized
          ? t(($) => $.pluginSettingsTab.attachmentOperationTemplates.customized)
          : t(($) => $.pluginSettingsTab.attachmentOperationTemplates.default);
      },
      items: params.items,
      name: params.name,
      type: 'page'
    };
  }

  /**
   * One nested page per operation. Each holds that operation's template rows, and its entry says whether any of them
   * departs from the default. Obsidian's declarative settings have no collapsible group, so a page is the native way to
   * fold an operation away until it is wanted.
   *
   * @returns The pages, in the order {@link ATTACHMENT_OPERATION_TEMPLATE_KEYS} lists the operations.
   */
  private getAttachmentOperationPages(): SettingDefinitionPage[] {
    return [
      this.getAttachmentOperationPage({
        description: t(($) => $.pluginSettingsTab.attachmentOperationTemplates.pastedImage.description),
        items: this.getNewAttachmentOperationTemplateItems({
          description: t(($) => $.pluginSettingsTab.attachmentOperationTemplates.pastedImage.description),
          fileName: t(($) => $.pluginSettingsTab.attachmentOperationTemplates.pastedImage.fileName),
          folderPath: t(($) => $.pluginSettingsTab.attachmentOperationTemplates.pastedImage.folderPath),
          operation: AttachmentOperation.PastedImage
        }),
        name: t(($) => $.pluginSettingsTab.attachmentOperationTemplates.pastedImage.name),
        operation: AttachmentOperation.PastedImage
      }),
      this.getAttachmentOperationPage({
        description: t(($) => $.pluginSettingsTab.attachmentOperationTemplates.pastedFile.description),
        items: this.getNewAttachmentOperationTemplateItems({
          description: t(($) => $.pluginSettingsTab.attachmentOperationTemplates.pastedFile.description),
          fileName: t(($) => $.pluginSettingsTab.attachmentOperationTemplates.pastedFile.fileName),
          folderPath: t(($) => $.pluginSettingsTab.attachmentOperationTemplates.pastedFile.folderPath),
          operation: AttachmentOperation.PastedFile
        }),
        name: t(($) => $.pluginSettingsTab.attachmentOperationTemplates.pastedFile.name),
        operation: AttachmentOperation.PastedFile
      }),
      this.getAttachmentOperationPage({
        description: t(($) => $.pluginSettingsTab.attachmentOperationTemplates.droppedFile.description),
        items: this.getNewAttachmentOperationTemplateItems({
          description: t(($) => $.pluginSettingsTab.attachmentOperationTemplates.droppedFile.description),
          fileName: t(($) => $.pluginSettingsTab.attachmentOperationTemplates.droppedFile.fileName),
          folderPath: t(($) => $.pluginSettingsTab.attachmentOperationTemplates.droppedFile.folderPath),
          operation: AttachmentOperation.DroppedFile
        }),
        name: t(($) => $.pluginSettingsTab.attachmentOperationTemplates.droppedFile.name),
        operation: AttachmentOperation.DroppedFile
      }),
      this.getAttachmentOperationPage({
        description: t(($) => $.pluginSettingsTab.attachmentOperationTemplates.other.description),
        items: this.getNewAttachmentOperationTemplateItems({
          description: t(($) => $.pluginSettingsTab.attachmentOperationTemplates.other.description),
          fileName: t(($) => $.pluginSettingsTab.attachmentOperationTemplates.other.fileName),
          folderPath: t(($) => $.pluginSettingsTab.attachmentOperationTemplates.other.folderPath),
          operation: AttachmentOperation.OtherNewAttachment
        }),
        name: t(($) => $.pluginSettingsTab.attachmentOperationTemplates.other.name),
        operation: AttachmentOperation.OtherNewAttachment
      }),
      this.getAttachmentOperationPage({
        description: t(($) => $.pluginSettingsTab.attachmentOperationTemplates.collect.description),
        // The switch is part of the operation's state: on, collecting renames, which is a departure from the default.
        isCustomized: () => this.pluginSettingsComponent.settings.shouldRenameCollectedAttachments,
        items: [
          this.settingEx({
            desc: translateFragment(($) => $.pluginSettingsTab.shouldRenameCollectedAttachments.description, {
              command: collectAttachmentsCommandNode(),
              setting: collectedAttachmentFileNameSettingNode()
            }),
            name: t(($) => $.pluginSettingsTab.shouldRenameCollectedAttachments.name),
            render: (setting) => {
              setting.addToggle((toggle) => {
                this.bind({
                  propertyName: 'shouldRenameCollectedAttachments',
                  valueComponent: toggle
                });
              });
            }
          }),
          this.settingEx({
            desc: translateFragment(($) => $.pluginSettingsTab.collectedAttachmentFileName.description, { tokens: tokensLinkNode() }),
            name: t(($) => $.pluginSettingsTab.collectedAttachmentFileName.name),
            render: (setting) => {
              setting.addCodeHighlighter((codeHighlighter) => {
                codeHighlighter.setLanguage(TOKENIZED_STRING_LANGUAGE);
                codeHighlighter.inputEl.addClass('tokenized-string-setting-control');
                this.bind({
                  propertyName: 'collectedAttachmentFileName',
                  valueComponent: codeHighlighter,
                  ...bindOptionsWithTrim
                });
              });
            }
          }),
          this.settingEx({
            desc: translateFragment(($) => $.pluginSettingsTab.collectedAttachmentFolderPath.description, {
              command: collectAttachmentsCommandNode(),
              relativePrefix: codeNode('./'),
              tokens: tokensLinkNode()
            }),
            name: t(($) => $.pluginSettingsTab.collectedAttachmentFolderPath.name),
            render: (setting) => {
              setting.addCodeHighlighter((codeHighlighter) => {
                codeHighlighter.setLanguage(TOKENIZED_STRING_LANGUAGE);
                codeHighlighter.inputEl.addClass('tokenized-string-setting-control');
                this.bind({
                  propertyName: 'collectedAttachmentFolderPath',
                  valueComponent: codeHighlighter,
                  ...bindOptionsWithTrim
                });
              });
            }
          })
        ],
        name: t(($) => $.pluginSettingsTab.attachmentOperationTemplates.collect.name),
        operation: AttachmentOperation.Collect
      }),
      this.getAttachmentOperationPage({
        description: t(($) => $.pluginSettingsTab.attachmentOperationTemplates.noteRename.description),
        items: [
          this.settingEx({
            desc: translateFragment(($) => $.pluginSettingsTab.renamedAttachmentFileName.description, { tokens: tokensLinkNode() }),
            name: t(($) => $.pluginSettingsTab.renamedAttachmentFileName.name),
            render: (setting) => {
              setting.addCodeHighlighter((codeHighlighter) => {
                codeHighlighter.setLanguage(TOKENIZED_STRING_LANGUAGE);
                codeHighlighter.inputEl.addClass('tokenized-string-setting-control');
                this.bind({
                  propertyName: 'renamedAttachmentFileName',
                  valueComponent: codeHighlighter,
                  ...bindOptionsWithTrim
                });
              });
            }
          })
        ],
        name: t(($) => $.pluginSettingsTab.attachmentOperationTemplates.noteRename.name),
        operation: AttachmentOperation.NoteRename
      }),
      this.getAttachmentOperationPage({
        description: t(($) => $.pluginSettingsTab.attachmentOperationTemplates.renameCommand.description),
        items: [
          this.settingEx({
            desc: translateFragment(($) => $.pluginSettingsTab.manuallyRenamedAttachmentFileName.description, {
              command: renameAttachmentsCommandNode(),
              tokens: tokensLinkNode()
            }),
            name: t(($) => $.pluginSettingsTab.manuallyRenamedAttachmentFileName.name),
            render: (setting) => {
              setting.addCodeHighlighter((codeHighlighter) => {
                codeHighlighter.setLanguage(TOKENIZED_STRING_LANGUAGE);
                codeHighlighter.inputEl.addClass('tokenized-string-setting-control');
                this.bind({
                  propertyName: 'manuallyRenamedAttachmentFileName',
                  valueComponent: codeHighlighter,
                  ...bindOptionsWithTrim
                });
              });
            }
          })
        ],
        name: t(($) => $.pluginSettingsTab.attachmentOperationTemplates.renameCommand.name),
        operation: AttachmentOperation.RenameCommand
      })
    ];
  }

  private getCollectedAttachmentsItems(): SettingDefinitionRender[] {
    return [
      this.settingEx({
        desc: t(($) => $.pluginSettingsTab.downloadNetworkImages.description),
        name: t(($) => $.pluginSettingsTab.downloadNetworkImages.name),
        render: (setting) => {
          setting.addToggle((toggle) => {
            this.bind({
              onChanged: () => {
                // Only the timeout row below reads this value, through its `visible` predicate.
                this.refreshDomState();
              },
              propertyName: 'downloadNetworkImages',
              valueComponent: toggle
            });
          });
        }
      }),
      this.settingEx({
        desc: t(($) => $.pluginSettingsTab.networkImageDownloadTimeoutInSeconds.description),
        name: t(($) => $.pluginSettingsTab.networkImageDownloadTimeoutInSeconds.name),
        render: (setting) => {
          setting.addNumber(($number) => {
            $number.setMin(1);
            this.bind({
              propertyName: 'networkImageDownloadTimeoutInSeconds',
              valueComponent: $number
            });
          });
        },
        visible: () => this.pluginSettingsComponent.settings.downloadNetworkImages
      }),
      this.settingEx({
        desc: createFragment((f) => {
          f.appendText(t(($) => $.pluginSettingsTab.collectAttachmentUsedByMultipleNotesMode.description));
          f.createEl('br');
          appendCodeBlock(f, t(($) => $.pluginSettings.collectAttachmentUsedByMultipleNotesMode.skip.displayText));
          f.appendText(' - ');
          f.appendText(t(($) => $.pluginSettings.collectAttachmentUsedByMultipleNotesMode.skip.description));
          f.createEl('br');
          appendCodeBlock(f, t(($) => $.pluginSettings.collectAttachmentUsedByMultipleNotesMode.move.displayText));
          f.appendText(' - ');
          f.appendText(t(($) => $.pluginSettings.collectAttachmentUsedByMultipleNotesMode.move.description));
          f.createEl('br');
          appendCodeBlock(f, t(($) => $.pluginSettings.collectAttachmentUsedByMultipleNotesMode.copy.displayText));
          f.appendText(' - ');
          f.appendText(t(($) => $.pluginSettings.collectAttachmentUsedByMultipleNotesMode.copy.description));
          f.createEl('br');
          appendCodeBlock(f, t(($) => $.pluginSettings.collectAttachmentUsedByMultipleNotesMode.cancel.displayText));
          f.appendText(' - ');
          f.appendText(t(($) => $.pluginSettings.collectAttachmentUsedByMultipleNotesMode.cancel.description));
          f.createEl('br');
          appendCodeBlock(f, t(($) => $.pluginSettings.collectAttachmentUsedByMultipleNotesMode.prompt.displayText));
          f.appendText(' - ');
          f.appendText(t(($) => $.pluginSettings.collectAttachmentUsedByMultipleNotesMode.prompt.description));
        }),
        name: t(($) => $.pluginSettingsTab.collectAttachmentUsedByMultipleNotesMode.name),
        render: (setting) => {
          setting.addDropdown((dropdown) => {
            dropdown.addOptions({
              /* eslint-disable perfectionist/sort-objects -- Need to keep enum order. */
              [CollectAttachmentUsedByMultipleNotesMode.Skip]: t(($) => $.pluginSettings.collectAttachmentUsedByMultipleNotesMode.skip.displayText),
              [CollectAttachmentUsedByMultipleNotesMode.Move]: t(($) => $.pluginSettings.collectAttachmentUsedByMultipleNotesMode.move.displayText),
              [CollectAttachmentUsedByMultipleNotesMode.Copy]: t(($) => $.pluginSettings.collectAttachmentUsedByMultipleNotesMode.copy.displayText),
              [CollectAttachmentUsedByMultipleNotesMode.Cancel]: t(($) => $.pluginSettings.collectAttachmentUsedByMultipleNotesMode.cancel.displayText),
              [CollectAttachmentUsedByMultipleNotesMode.Prompt]: t(($) => $.pluginSettings.collectAttachmentUsedByMultipleNotesMode.prompt.displayText)
              /* eslint-enable perfectionist/sort-objects -- Need to keep enum order. */
            });
            this.bind({
              propertyName: 'collectAttachmentUsedByMultipleNotesMode',
              valueComponent: dropdown
            });
          });
        }
      }),
      this.settingEx({
        desc: t(($) => $.pluginSettingsTab.shouldSkipCollectingAttachmentsReferencedByRawPath.description),
        name: t(($) => $.pluginSettingsTab.shouldSkipCollectingAttachmentsReferencedByRawPath.name),
        render: (setting) => {
          setting.addToggle((toggle) => {
            this.bind({
              propertyName: 'shouldSkipCollectingAttachmentsReferencedByRawPath',
              valueComponent: toggle
            });
          });
        }
      }),
      this.settingEx({
        desc: t(($) => $.pluginSettingsTab.shouldCollectAttachmentsAutomatically.description),
        name: t(($) => $.pluginSettingsTab.shouldCollectAttachmentsAutomatically.name),
        render: (setting) => {
          setting.addToggle((toggle) => {
            this.bind({
              propertyName: 'shouldCollectAttachmentsAutomatically',
              valueComponent: toggle
            });
          });
        }
      })
    ];
  }

  private getCoreItems(): SettingDefinitionRender[] {
    return [
      this.settingEx({
        desc: t(($) => $.pluginSettingsTab.shouldFollowObsidianAttachmentLocation.description),
        name: t(($) => $.pluginSettingsTab.shouldFollowObsidianAttachmentLocation.name),
        render: (setting) => {
          setting.addToggle((toggle) => {
            this.bind({
              onChanged: () => {
                // Only the template row below reads this value, through its `visible` predicate.
                this.refreshDomState();
              },
              propertyName: 'shouldFollowObsidianAttachmentLocation',
              valueComponent: toggle
            });
          });
        }
      }),
      this.settingEx({
        desc: translateFragment(($) => $.pluginSettingsTab.locationForNewAttachments.description, {
          dotFolder: codeNode('.attachments'),
          relativePrefix: codeNode('.'),
          tokens: tokensLinkNode(),
          unhidePlugin: linkNode('https://community.obsidian.md/plugins/unhide', 'Unhide')
        }),
        name: t(($) => $.pluginSettingsTab.locationForNewAttachments.name),
        render: (setting) => {
          setting.addCodeHighlighter((codeHighlighter) => {
            codeHighlighter.setLanguage(TOKENIZED_STRING_LANGUAGE);
            codeHighlighter.inputEl.addClass('tokenized-string-setting-control');
            this.bind({
              propertyName: 'attachmentFolderPath',
              valueComponent: codeHighlighter,
              ...bindOptionsWithTrim
            });
          });
        },
        visible: () => !this.pluginSettingsComponent.settings.shouldFollowObsidianAttachmentLocation
      }),
      this.settingEx({
        desc: translateFragment(($) => $.pluginSettingsTab.generatedAttachmentFileName.description, { tokens: tokensLinkNode() }),
        name: t(($) => $.pluginSettingsTab.generatedAttachmentFileName.name),
        render: (setting) => {
          setting.addCodeHighlighter((codeHighlighter) => {
            codeHighlighter.setLanguage(TOKENIZED_STRING_LANGUAGE);
            codeHighlighter.inputEl.addClass('tokenized-string-setting-control');
            this.bind({
              propertyName: 'generatedAttachmentFileName',
              valueComponent: codeHighlighter,
              ...bindOptionsWithTrim
            });
          });
        }
      }),
      this.settingEx({
        desc: t(($) => $.pluginSettingsTab.sidecarExtensions.description),
        name: t(($) => $.pluginSettingsTab.sidecarExtensions.name),
        render: (setting) => {
          setting.addMultipleText((multipleText) => {
            this.bind({
              propertyName: 'sidecarExtensions',
              // An empty list is a real value, "pair nothing", so clearing must not snap back to the defaults, and the box must show the list as it is.
              shouldResetSettingWhenComponentIsEmpty: false,
              shouldShowPlaceholderForDefaultValues: false,
              valueComponent: multipleText
            });
          });
          setting.addExtraButton((button) => {
            button.setIcon('rotate-ccw');
            button.setTooltip(t(($) => $.pluginSettingsTab.sidecarExtensions.resetToDefault));
            button.onClick(convertAsyncToSync(async () => {
              await this.pluginSettingsComponent.editAndSave((settings) => {
                settings.sidecarExtensions = new PluginSettings().sidecarExtensions;
              });
              this.refresh();
            }));
          });
        }
      }),
      this.settingEx({
        desc: translateFragment(($) => $.pluginSettingsTab.shouldWarnWhenOriginalAttachmentNameIsUnknown.description, {
          currentNameToken: codeNode('{{attachmentFileName}}'),
          originalNameToken: codeNode('{{originalAttachmentFileName}}')
        }),
        name: t(($) => $.pluginSettingsTab.shouldWarnWhenOriginalAttachmentNameIsUnknown.name),
        render: (setting) => {
          setting.addToggle((toggle) => {
            this.bind({
              propertyName: 'shouldWarnWhenOriginalAttachmentNameIsUnknown',
              valueComponent: toggle
            });
          });
        }
      })
    ];
  }

  private getCustomTokensItems(): SettingDefinitionRender[] {
    return [
      this.settingEx({
        desc: translateFragment(($) => $.pluginSettingsTab.customTokens.description, {
          documentation: linkNode(CUSTOM_TOKENS_DOCUMENTATION_URL, t(($) => $.links.documentation))
        }),
        name: t(($) => $.pluginSettingsTab.customTokens.name),
        render: (setting) => {
          // Render-time setup: the builder must stay pure, because Obsidian calls it at plugin load to
          // index the settings for search. `hide()` clears the flag again.
          this.pluginSettingsComponent2.shouldDebounceCustomTokensValidation = true;
          // eslint-disable-next-line unicorn/name-replacements -- `customTokensStr` is a persisted `data.json` settings key; renaming it would silently drop the user's custom tokens.
          const registerCustomTokensDebounced = debounce((customTokensStr: string) => {
            invokeAsyncSafely(async () => {
              Substitutions.registerCustomTokens(customTokensStr);
              await this.revalidate();
            });
          }, REGISTER_CUSTOM_TOKENS_DEBOUNCE_IN_MILLISECONDS);

          setting.addCodeHighlighter((codeHighlighter) => {
            codeHighlighter.setLanguage('javascript');
            codeHighlighter.inputEl.addClass('custom-tokens-setting-control');
            this.bind({
              onChanged: (newValue) => {
                registerCustomTokensDebounced(newValue);
              },
              propertyName: 'customTokensStr',
              valueComponent: codeHighlighter
            });
          });

          return () => {
            registerCustomTokensDebounced.cancel();
          };
        }
      }),
      this.settingEx({
        name: '',
        render: (setting) => {
          setting.addButton((button) => {
            button.setButtonText(t(($) => $.pluginSettingsTab.resetToSampleCustomTokens.title));
            button.setDestructive();
            button.onClick(convertAsyncToSync(async () => {
              if (
                (this.pluginSettingsComponent.settings.customTokensStr === SAMPLE_CUSTOM_TOKENS) || (this.pluginSettingsComponent.settings.customTokensStr !== '' && !await confirm({
                  app: this.app,
                  cancelButtonText: t(($) => $.obsidianLib.buttons.cancel),
                  message: t(($) => $.pluginSettingsTab.resetToSampleCustomTokens.message),
                  okButtonText: t(($) => $.obsidianLib.buttons.ok),
                  title: t(($) => $.pluginSettingsTab.resetToSampleCustomTokens.title)
                }))
              ) {
                return;
              }

              await this.pluginSettingsComponent.editAndSave((settings) => {
                // eslint-disable-next-line unicorn/name-replacements -- `customTokensStr` is a persisted `data.json` settings key; renaming it would silently drop the user's custom tokens.
                settings.customTokensStr = SAMPLE_CUSTOM_TOKENS;
              });
              this.refresh();
            }));
          });
        },
        // The row is a bare action button with no name, so there is nothing to match on.
        searchable: false
      })
    ];
  }

  private getImagesItems(): SettingDefinitionRender[] {
    return [
      this.settingEx({
        desc: translateFragment(($) => $.pluginSettingsTab.defaultImageSize.description, {
          percentage: codeNode('50%'),
          pixels: codeNode('300px')
        }),
        name: t(($) => $.pluginSettingsTab.defaultImageSize.name),
        render: (setting) => {
          setting
            .addText((text) => {
              this.bind({
                propertyName: 'defaultImageSize',
                valueComponent: text
              });
            })
            .addDropdown((dropdown) => {
              // A sub-page renders outside the tab's container, so the plugin's scope class has to be on the control itself.
              addPluginCssClasses(dropdown.selectEl, 'default-image-size-dimension-setting-control');
              dropdown.addOptions({
                /* eslint-disable perfectionist/sort-objects -- Need to keep enum order. */
                [DefaultImageSizeDimension.Width]: t(($) => $.pluginSettings.defaultImageSizeDimension.width),
                [DefaultImageSizeDimension.Height]: t(($) => $.pluginSettings.defaultImageSizeDimension.height)
                /* eslint-enable perfectionist/sort-objects -- Need to keep enum order. */
              });
              this.bind({
                propertyName: 'defaultImageSizeDimension',
                valueComponent: dropdown
              });
            });
        }
      }),
      this.settingEx({
        desc: createFragment((f) => {
          f.appendText(t(($) => $.pluginSettingsTab.convertImagesToJpegMode.description));
          f.createEl('br');
          appendCodeBlock(f, t(($) => $.pluginSettings.convertImagesToJpegMode.none.displayText));
          f.appendText(' - ');
          f.appendText(t(($) => $.pluginSettings.convertImagesToJpegMode.none.description));
          f.createEl('br');
          appendCodeBlock(f, t(($) => $.pluginSettings.convertImagesToJpegMode.onlyPastedClipboardPngImages.displayText));
          f.appendText(' - ');
          f.appendText(t(($) => $.pluginSettings.convertImagesToJpegMode.onlyPastedClipboardPngImages.description));
          f.createEl('br');
          appendCodeBlock(f, t(($) => $.pluginSettings.convertImagesToJpegMode.allImagesExceptAlreadyJpeg.displayText));
          f.appendText(' - ');
          f.appendText(t(($) => $.pluginSettings.convertImagesToJpegMode.allImagesExceptAlreadyJpeg.description));
          f.createEl('br');
          appendCodeBlock(f, t(($) => $.pluginSettings.convertImagesToJpegMode.allImages.displayText));
          f.appendText(' - ');
          f.appendText(t(($) => $.pluginSettings.convertImagesToJpegMode.allImages.description));
        }),
        name: t(($) => $.pluginSettingsTab.convertImagesToJpegMode.name),
        render: (setting) => {
          setting.addDropdown((dropdown) => {
            dropdown.addOptions({
              /* eslint-disable perfectionist/sort-objects -- Need to keep enum order. */
              [ConvertImagesToJpegMode.None]: t(($) => $.pluginSettings.convertImagesToJpegMode.none.displayText),
              [ConvertImagesToJpegMode.OnlyPastedClipboardPngImages]: t(($) => $.pluginSettings.convertImagesToJpegMode.onlyPastedClipboardPngImages.displayText),
              [ConvertImagesToJpegMode.AllImagesExceptAlreadyJpegFiles]: t(($) => $.pluginSettings.convertImagesToJpegMode.allImagesExceptAlreadyJpeg.displayText),
              [ConvertImagesToJpegMode.AllImages]: t(($) => $.pluginSettings.convertImagesToJpegMode.allImages.displayText)
              /* eslint-enable perfectionist/sort-objects -- Need to keep enum order. */
            });
            this.bind({
              onChanged: () => {
                // The metadata row below only reads this value through its `disabled` predicate.
                this.refreshDomState();
              },
              propertyName: 'convertImagesToJpegMode',
              valueComponent: dropdown
            });
          });
        }
      }),
      this.settingEx({
        desc: t(($) => $.pluginSettingsTab.jpegQuality.description),
        name: t(($) => $.pluginSettingsTab.jpegQuality.name),
        render: (setting) => {
          setting.addDropdown((dropDown) => {
            dropDown.addOptions(generateJpegQualityOptions());
            this.bind({
              componentToPluginSettingsValueConverter: Number,
              pluginSettingsToComponentValueConverter: (value) => value.toPrecision(JPEG_QUALITY_PRECISION),
              propertyName: 'jpegQuality',
              valueComponent: dropDown
            });
          });
        }
      }),
      this.settingEx({
        desc: translateFragment(($) => $.pluginSettingsTab.shouldPreserveImageMetadata.description, {}),
        disabled: () => this.pluginSettingsComponent.settings.convertImagesToJpegMode === ConvertImagesToJpegMode.None,
        name: t(($) => $.pluginSettingsTab.shouldPreserveImageMetadata.name),
        render: (setting) => {
          setting.addToggle((toggle) => {
            this.bind({
              propertyName: 'shouldPreserveImageMetadata',
              valueComponent: toggle
            });
          });
        }
      })
    ];
  }

  private getMoveRenamesItems(): SettingDefinitionRender[] {
    return [
      this.settingEx({
        desc: translateFragment(($) => $.pluginSettingsTab.duplicateNameSeparator.description, {
          existingFile: codeNode('existingFile.pdf'),
          firstAvailableName: codeNode('existingFile 1.pdf'),
          secondAvailableName: codeNode('existingFile 2.pdf')
        }),
        name: t(($) => $.pluginSettingsTab.duplicateNameSeparator.name),
        render: (setting) => {
          setting.addText((text) => {
            this.bind({
              componentToPluginSettingsValueConverter: restoreSpaceCharacter,
              pluginSettingsToComponentValueConverter: showSpaceCharacter,
              propertyName: 'duplicateNameSeparator',
              valueComponent: text
            });

            handleWhitespace(text);
          });
        }
      }),
      this.settingEx({
        desc: t(($) => $.pluginSettingsTab.shouldDeduplicateIdenticalAttachments.description),
        name: t(($) => $.pluginSettingsTab.shouldDeduplicateIdenticalAttachments.name),
        render: (setting) => {
          setting.addToggle((toggle) => {
            this.bind({
              propertyName: 'shouldDeduplicateIdenticalAttachments',
              valueComponent: toggle
            });
          });
        }
      }),
      this.settingEx({
        desc: createFragment((f) => {
          f.appendText(t(($) => $.pluginSettingsTab.attachmentRenameMode.description));
          f.createEl('br');
          appendCodeBlock(f, t(($) => $.pluginSettings.attachmentRenameMode.none.displayText));
          f.appendText(' - ');
          f.appendText(t(($) => $.pluginSettings.attachmentRenameMode.none.description));
          f.createEl('br');
          appendCodeBlock(f, t(($) => $.pluginSettings.attachmentRenameMode.onlyPastedImages.displayText));
          f.appendText(' - ');
          f.appendText(t(($) => $.pluginSettings.attachmentRenameMode.onlyPastedImages.description));
          f.createEl('br');
          appendCodeBlock(f, t(($) => $.pluginSettings.attachmentRenameMode.all.displayText));
          f.appendText(' - ');
          f.appendText(t(($) => $.pluginSettings.attachmentRenameMode.all.description));
        }),
        name: t(($) => $.pluginSettingsTab.attachmentRenameMode.name),
        render: (setting) => {
          setting.addDropdown((dropdown) => {
            dropdown.addOptions({
              /* eslint-disable perfectionist/sort-objects -- Need to keep enum order. */
              [AttachmentRenameMode.None]: t(($) => $.pluginSettings.attachmentRenameMode.none.displayText),
              [AttachmentRenameMode.OnlyPastedImages]: t(($) => $.pluginSettings.attachmentRenameMode.onlyPastedImages.displayText),
              [AttachmentRenameMode.All]: t(($) => $.pluginSettings.attachmentRenameMode.all.displayText)
              /* eslint-enable perfectionist/sort-objects -- Need to keep enum order. */
            });
            this.bind({
              propertyName: 'attachmentRenameMode',
              valueComponent: dropdown
            });
          });
        }
      }),
      this.settingEx({
        desc: t(($) => $.pluginSettingsTab.shouldKeepNamesOfPastedNonScreenshotFiles.description),
        name: t(($) => $.pluginSettingsTab.shouldKeepNamesOfPastedNonScreenshotFiles.name),
        render: (setting) => {
          setting.addToggle((toggle) => {
            this.bind({
              propertyName: 'shouldKeepNamesOfPastedNonScreenshotFiles',
              valueComponent: toggle
            });
          });
        }
      }),
      this.settingEx({
        desc: translateFragment(($) => $.pluginSettingsTab.screenshotFilePaths.description, {
          regularExpression: codeNode(t(($) => $.regularExpression))
        }),
        name: t(($) => $.pluginSettingsTab.screenshotFilePaths.name),
        render: (setting) => {
          setting.addMultipleText((multipleText) => {
            this.bind({
              propertyName: 'screenshotFilePaths',
              valueComponent: multipleText
            });
          });
        }
      }),
      this.settingEx({
        desc: translateFragment(($) => $.pluginSettingsTab.renameAttachmentsCreatedByOtherPluginsMode.description, {
          modes: (parent) => {
            appendCodeBlock(parent, t(($) => $.pluginSettings.renameAttachmentsCreatedByOtherPluginsMode.none.displayText));
            parent.appendText(' - ');
            parent.appendText(t(($) => $.pluginSettings.renameAttachmentsCreatedByOtherPluginsMode.none.description));
            parent.createEl('br');
            appendCodeBlock(parent, t(($) => $.pluginSettings.renameAttachmentsCreatedByOtherPluginsMode.all.displayText));
            parent.appendText(' - ');
            parent.appendText(t(($) => $.pluginSettings.renameAttachmentsCreatedByOtherPluginsMode.all.description));
            parent.createEl('br');
            appendCodeBlock(parent, t(($) => $.pluginSettings.renameAttachmentsCreatedByOtherPluginsMode.onlyListedPlugins.displayText));
            parent.appendText(' - ');
            parent.appendText(t(($) => $.pluginSettings.renameAttachmentsCreatedByOtherPluginsMode.onlyListedPlugins.description));
            parent.createEl('br');
            appendCodeBlock(parent, t(($) => $.pluginSettings.renameAttachmentsCreatedByOtherPluginsMode.allExceptListedPlugins.displayText));
            parent.appendText(' - ');
            parent.appendText(t(($) => $.pluginSettings.renameAttachmentsCreatedByOtherPluginsMode.allExceptListedPlugins.description));
          }
        }),
        name: t(($) => $.pluginSettingsTab.renameAttachmentsCreatedByOtherPluginsMode.name),
        render: (setting) => {
          setting.addDropdown((dropdown) => {
            dropdown.addOptions({
              /* eslint-disable perfectionist/sort-objects -- Need to keep enum order. */
              [RenameAttachmentsCreatedByOtherPluginsMode.None]: t(($) => $.pluginSettings.renameAttachmentsCreatedByOtherPluginsMode.none.displayText),
              [RenameAttachmentsCreatedByOtherPluginsMode.All]: t(($) => $.pluginSettings.renameAttachmentsCreatedByOtherPluginsMode.all.displayText),
              [RenameAttachmentsCreatedByOtherPluginsMode.OnlyListedPlugins]: t(($) => $.pluginSettings.renameAttachmentsCreatedByOtherPluginsMode.onlyListedPlugins.displayText),
              [RenameAttachmentsCreatedByOtherPluginsMode.AllExceptListedPlugins]: t(($) => $.pluginSettings.renameAttachmentsCreatedByOtherPluginsMode.allExceptListedPlugins.displayText)
              /* eslint-enable perfectionist/sort-objects -- Need to keep enum order. */
            });
            this.bind({
              onChanged: () => {
                // The plugin list below is only shown for the two list modes, via its `visible` predicate.
                this.refreshDomState();
              },
              propertyName: 'renameAttachmentsCreatedByOtherPluginsMode',
              valueComponent: dropdown
            });
          });
        }
      }),
      this.settingEx({
        desc: translateFragment(($) => $.pluginSettingsTab.otherPluginIdsForAttachmentRename.description, {}),
        name: t(($) => $.pluginSettingsTab.otherPluginIdsForAttachmentRename.name),
        render: (setting) => {
          setting.addMultipleDropdown((multipleDropdown) => {
            multipleDropdown.addOptions(this.getSelectablePluginOptions());
            this.bind({
              propertyName: 'otherPluginIdsForAttachmentRename',
              valueComponent: multipleDropdown
            });
          });
        },
        visible: () => this.pluginSettingsComponent.settings.needsCreatingPluginAttribution()
      }),
      this.settingEx({
        desc: createFragment((f) => {
          f.appendText(t(($) => $.pluginSettingsTab.moveAttachmentToProperFolderUsedByMultipleNotesMode.description));
          f.createEl('br');
          appendCodeBlock(f, t(($) => $.pluginSettings.moveAttachmentToProperFolderUsedByMultipleNotesMode.skip.displayText));
          f.appendText(' - ');
          f.appendText(t(($) => $.pluginSettings.moveAttachmentToProperFolderUsedByMultipleNotesMode.skip.description));
          f.createEl('br');
          appendCodeBlock(f, t(($) => $.pluginSettings.moveAttachmentToProperFolderUsedByMultipleNotesMode.copyAll.displayText));
          f.appendText(' - ');
          f.appendText(t(($) => $.pluginSettings.moveAttachmentToProperFolderUsedByMultipleNotesMode.copyAll.description));
          f.createEl('br');
          appendCodeBlock(f, t(($) => $.pluginSettings.moveAttachmentToProperFolderUsedByMultipleNotesMode.cancel.displayText));
          f.appendText(' - ');
          f.appendText(t(($) => $.pluginSettings.moveAttachmentToProperFolderUsedByMultipleNotesMode.cancel.description));
          f.createEl('br');
          appendCodeBlock(f, t(($) => $.pluginSettings.moveAttachmentToProperFolderUsedByMultipleNotesMode.prompt.displayText));
          f.appendText(' - ');
          f.appendText(t(($) => $.pluginSettings.moveAttachmentToProperFolderUsedByMultipleNotesMode.prompt.description));
        }),
        name: t(($) => $.pluginSettingsTab.moveAttachmentToProperFolderUsedByMultipleNotesMode.name),
        render: (setting) => {
          setting.addDropdown((dropdown) => {
            dropdown.addOptions({
              /* eslint-disable perfectionist/sort-objects -- Need to keep enum order. */
              [MoveAttachmentToProperFolderUsedByMultipleNotesMode.Skip]: t(($) => $.pluginSettings.moveAttachmentToProperFolderUsedByMultipleNotesMode.skip.displayText),
              [MoveAttachmentToProperFolderUsedByMultipleNotesMode.CopyAll]: t(($) => $.pluginSettings.moveAttachmentToProperFolderUsedByMultipleNotesMode.copyAll.displayText),
              [MoveAttachmentToProperFolderUsedByMultipleNotesMode.Cancel]: t(($) => $.pluginSettings.moveAttachmentToProperFolderUsedByMultipleNotesMode.cancel.displayText),
              [MoveAttachmentToProperFolderUsedByMultipleNotesMode.Prompt]: t(($) => $.pluginSettings.moveAttachmentToProperFolderUsedByMultipleNotesMode.prompt.displayText)
              /* eslint-enable perfectionist/sort-objects -- Need to keep enum order. */
            });
            this.bind({
              propertyName: 'moveAttachmentToProperFolderUsedByMultipleNotesMode',
              valueComponent: dropdown
            });
          });
        }
      })
    ];
  }

  private getNewAttachmentOperationTemplateItem(params: PluginSettingsTabGetNewAttachmentOperationTemplateItemParams): SettingDefinitionRender {
    return this.settingEx({
      desc: createFragment((f) => {
        f.appendText(params.description);
        f.createEl('br');
        f.createEl('a', {
          href: TOKEN_REFERENCE_DOCUMENTATION_URL,
          text: t(($) => $.pluginSettingsTab.attachmentOperationTemplates.tokens)
        });
        f.appendText('.');
        f.createEl('br');
        f.appendText(params.hint);
      }),
      name: params.name,
      render: (setting) => {
        setting.addCodeHighlighter((codeHighlighter) => {
          codeHighlighter.setLanguage(TOKENIZED_STRING_LANGUAGE);
          codeHighlighter.inputEl.addClass('tokenized-string-setting-control');
          this.bind({
            propertyName: params.propertyName,
            valueComponent: codeHighlighter,
            ...bindOptionsWithTrim
          });
        });
      }
    });
  }

  /**
   * The folder row and the file name row of one new-attachment operation, each empty meaning the default.
   *
   * @param params - The operation and its labels.
   * @returns The two rows.
   */
  private getNewAttachmentOperationTemplateItems(params: PluginSettingsTabGetNewAttachmentOperationTemplateItemsParams): SettingDefinitionRender[] {
    const keys = ATTACHMENT_OPERATION_TEMPLATE_KEYS[params.operation];
    return [
      this.getNewAttachmentOperationTemplateItem({
        description: params.description,
        hint: t(($) => $.pluginSettingsTab.attachmentOperationTemplates.folderPathDescription),
        name: params.folderPath,
        propertyName: ensureNonNullable(keys.folderPath)
      }),
      this.getNewAttachmentOperationTemplateItem({
        description: params.description,
        hint: t(($) => $.pluginSettingsTab.attachmentOperationTemplates.fileNameDescription),
        name: params.fileName,
        propertyName: keys.fileName
      })
    ];
  }

  private getPathItems(): SettingDefinitionRender[] {
    return [
      this.settingEx({
        desc: translateFragment(($) => $.pluginSettingsTab.attachmentUnitFolderPaths.description, {
          command: collectAttachmentsCommandNode(),
          pathSyntax: appendPathEntrySyntax
        }),
        name: t(($) => $.pluginSettingsTab.attachmentUnitFolderPaths.name),
        render: (setting) => {
          setting.addMultipleText((multipleText) => {
            this.bind({
              propertyName: 'attachmentUnitFolderPaths',
              valueComponent: multipleText
            });
          });
        }
      }),
      this.settingEx({
        desc: translateFragment(($) => $.pluginSettingsTab.excludePathsFromAttachmentCollecting.description, {
          command: collectAttachmentsCommandNode(),
          pathSyntax: appendPathEntrySyntax
        }),
        name: t(($) => $.pluginSettingsTab.excludePathsFromAttachmentCollecting.name),
        render: (setting) => {
          setting.addMultipleText((multipleText) => {
            this.bind({
              propertyName: 'excludePathsFromAttachmentCollecting',
              valueComponent: multipleText
            });
          });
        }
      }),
      this.settingEx({
        desc: translateFragment(($) => $.pluginSettingsTab.excludeExtensionsFromMultipleNotesCheck.description, {
          collectCommand: collectAttachmentsCommandNode(),
          compoundExtension: codeNode('excalidraw.md'),
          moveCommand: codeNode(t(($) => $.commands.moveAttachmentToProperFolder))
        }),
        name: t(($) => $.pluginSettingsTab.excludeExtensionsFromMultipleNotesCheck.name),
        render: (setting) => {
          setting.addMultipleText((multipleText) => {
            this.bind({
              propertyName: 'excludeExtensionsFromMultipleNotesCheck',
              valueComponent: multipleText
            });
          });
        }
      }),
      this.settingEx({
        desc: translateFragment(($) => $.pluginSettingsTab.excludePathsFromMultipleNotesCheck.description, {
          collectCommand: collectAttachmentsCommandNode(),
          moveCommand: codeNode(t(($) => $.commands.moveAttachmentToProperFolder)),
          pathSyntax: appendPathEntrySyntax
        }),
        name: t(($) => $.pluginSettingsTab.excludePathsFromMultipleNotesCheck.name),
        render: (setting) => {
          setting.addMultipleText((multipleText) => {
            this.bind({
              propertyName: 'excludePathsFromMultipleNotesCheck',
              valueComponent: multipleText
            });
          });
        }
      }),
      this.settingEx({
        desc: translateFragment(($) => $.pluginSettingsTab.orphanAttachmentScanMode.description, {
          command: codeNode(t(($) => $.commands.deleteUnusedAttachmentsEntireVault)),
          modes: (parent) => {
            appendCodeBlock(parent, t(($) => $.pluginSettings.orphanAttachmentScanMode.none.displayText));
            parent.appendText(' - ');
            parent.appendText(t(($) => $.pluginSettings.orphanAttachmentScanMode.none.description));
            parent.createEl('br');
            appendCodeBlock(parent, t(($) => $.pluginSettings.orphanAttachmentScanMode.listedPaths.displayText));
            parent.appendText(' - ');
            parent.appendText(t(($) => $.pluginSettings.orphanAttachmentScanMode.listedPaths.description));
            parent.createEl('br');
            appendCodeBlock(parent, t(($) => $.pluginSettings.orphanAttachmentScanMode.entireVault.displayText));
            parent.appendText(' - ');
            parent.appendText(t(($) => $.pluginSettings.orphanAttachmentScanMode.entireVault.description));
          }
        }),
        name: t(($) => $.pluginSettingsTab.orphanAttachmentScanMode.name),
        render: (setting) => {
          setting.addDropdown((dropdown) => {
            dropdown.addOptions({
              /* eslint-disable perfectionist/sort-objects -- Need to keep enum order. */
              [OrphanAttachmentScanMode.None]: t(($) => $.pluginSettings.orphanAttachmentScanMode.none.displayText),
              [OrphanAttachmentScanMode.ListedPaths]: t(($) => $.pluginSettings.orphanAttachmentScanMode.listedPaths.displayText),
              [OrphanAttachmentScanMode.EntireVault]: t(($) => $.pluginSettings.orphanAttachmentScanMode.entireVault.displayText)
              /* eslint-enable perfectionist/sort-objects -- Need to keep enum order. */
            });
            this.bind({
              onChanged: () => {
                // The path list below is only shown for the listed-paths mode, via its `visible` predicate.
                this.refreshDomState();
              },
              propertyName: 'orphanAttachmentScanMode',
              valueComponent: dropdown
            });
          });
        }
      }),
      this.settingEx({
        desc: translateFragment(($) => $.pluginSettingsTab.orphanAttachmentScanPaths.description, { pathSyntax: appendPathEntrySyntax }),
        name: t(($) => $.pluginSettingsTab.orphanAttachmentScanPaths.name),
        render: (setting) => {
          setting.addMultipleText((multipleText) => {
            this.bind({
              propertyName: 'orphanAttachmentScanPaths',
              valueComponent: multipleText
            });
          });
        },
        visible: () => this.pluginSettingsComponent.settings.needsOrphanAttachmentScanPaths()
      })
    ];
  }

  /**
   * The plugins offered in the picker, as plugin id -> display name.
   *
   * Built from the installed manifests so the user picks a plugin by NAME — the id is a folder name under
   * `.obsidian/plugins` that the Obsidian UI never shows, so asking for it by hand would be guesswork.
   *
   * Any id already stored is added back even when its plugin is currently disabled or no longer installed,
   * listed under the bare id since there is no manifest to name it. Without that, merely opening this tab
   * would drop the entry — the picker cannot hold a value it has no option for.
   *
   * @returns The options for the plugin picker.
   */
  private getSelectablePluginOptions(): Record<string, string> {
    const options: Record<string, string> = {};

    for (const manifest of Object.values(this.app.plugins.manifests)) {
      if (manifest.id === this.ownPluginId) {
        continue;
      }

      options[manifest.id] = manifest.name;
    }

    for (const pluginId of this.pluginSettingsComponent.settings.otherPluginIdsForAttachmentRename) {
      options[pluginId] ??= pluginId;
    }

    return options;
  }

  private getSpecialCharactersItems(): SettingDefinitionRender[] {
    return [
      this.settingEx({
        desc: translateFragment(($) => $.pluginSettingsTab.specialCharacters.description, {}),
        name: t(($) => $.pluginSettingsTab.specialCharacters.name),
        render: (setting) => {
          setting.addText((text) => {
            this.bind({
              componentToPluginSettingsValueConverter: restoreSpaceCharacter,
              pluginSettingsToComponentValueConverter: showSpaceCharacter,
              propertyName: 'specialCharacters',
              shouldResetSettingWhenComponentIsEmpty: false,
              shouldShowPlaceholderForDefaultValues: false,
              valueComponent: text
            });

            handleWhitespace(text);
          });
        }
      }),
      this.settingEx({
        desc: translateFragment(($) => $.pluginSettingsTab.specialCharactersReplacement.description, {}),
        name: t(($) => $.pluginSettingsTab.specialCharactersReplacement.name),
        render: (setting) => {
          setting.addText((text) => {
            this.bind({
              componentToPluginSettingsValueConverter: restoreSpaceCharacter,
              pluginSettingsToComponentValueConverter: showSpaceCharacter,
              propertyName: 'specialCharactersReplacement',
              shouldResetSettingWhenComponentIsEmpty: false,
              shouldShowPlaceholderForDefaultValues: false,
              valueComponent: text
            });
          });
        }
      })
    ];
  }

  private getStorageItems(): SettingDefinitionRender[] {
    return [
      this.settingEx({
        desc: t(($) => $.originalAttachmentNames.storage.folderDescription),
        name: t(($) => $.originalAttachmentNames.storage.folder),
        render: (setting) => {
          setting.addText((text) => {
            this.bind({ propertyName: 'pluginDataFolder', valueComponent: text });
          });
        }
      }),
      this.settingEx({
        desc: t(($) => $.originalAttachmentNames.storage.hiddenDescription),
        name: t(($) => $.originalAttachmentNames.storage.hidden),
        render: (setting) => {
          setting.addToggle((toggle) => {
            this.bind({ propertyName: 'shouldAllowHiddenPluginDataFolder', valueComponent: toggle });
          });
        }
      }),
      this.settingEx({
        name: t(($) => $.originalAttachmentNames.storage.title),
        render: (setting) => {
          const component = this.getOriginalAttachmentNamesComponent?.();
          if (!component) {
            return;
          }
          // A sub-page renders outside the tab's container, so the plugin's scope class has to be on the row itself.
          addPluginCssClasses(setting.settingEl, 'original-name-storage-controls');
          const storage: OriginalAttachmentNamesComponent = component;
          // The buttons are actions, not a choice that stays selected: the one that would change nothing is disabled.
          let disableButton: ButtonComponent | undefined;
          const updateDescription = (): void => {
            disableButton?.setDisabled(!storage.isSyncEnabled);
            const obsidianSyncStatus = getObsidianSyncStatus(this.app);
            const advice = getOriginalNameSyncAdvice({
              doesTemplateReadOriginalName: doesAnySettingReadOriginalAttachmentFileName(this.pluginSettingsComponent.settings),
              isObsidianSyncProvider: storage.isObsidianSyncProvider,
              isSyncEnabled: storage.isSyncEnabled,
              obsidianSyncState: obsidianSyncStatus.state
            });
            setting.setDesc(createFragment((fragment) => {
              const status = t(($) => storage.isSyncEnabled ? $.originalAttachmentNames.storage.enabled : $.originalAttachmentNames.storage.local);
              fragment.createEl('p', { text: status });
              const adviceText = getAdviceText(advice);
              if (adviceText) {
                fragment.createEl('p', { cls: 'original-name-storage-advice' }, (p) => {
                  p.append(createFragmentWithCodeBlocks(adviceText));
                });
              }
              fragment.createEl('p', { cls: 'original-name-storage-roots' }, (p) => {
                p.append(createFragmentWithCodeBlocks(t(($) => $.originalAttachmentNames.storage.roots, {
                  roots: storage.transportRoots.map((root) => asCodeBlock(root)).join(', ')
                })));
              });
              fragment.createEl('a', { href: 'https://help.obsidian.md/sync/settings', text: t(($) => $.originalAttachmentNames.storage.obsidianSync) });
            }));
          };
          const run = async (action: () => Promise<void>): Promise<void> => {
            try {
              await action();
            } catch (error) {
              await alert({ app: this.app, message: String(error), title: t(($) => $.originalAttachmentNames.storage.errorTitle) });
            } finally {
              updateDescription();
            }
          };
          const setup = async (isObsidianSync: boolean): Promise<void> => {
            if (isObsidianSync && (component.transportRoots.some((root) => root.split('/').some((segment) => segment.startsWith('.'))) || this.pluginSettingsComponent.settings.pluginDataFolder.split('/').some((segment) => segment.startsWith('.')))) {
              await alert({ app: this.app, message: t(($) => $.originalAttachmentNames.storage.hiddenObsidianSync) });
              return;
            }
            if (isObsidianSync) {
              const obsidianSyncStatus = getObsidianSyncStatus(this.app);
              if (obsidianSyncStatus.state !== ObsidianSyncState.Connected) {
                await alert({ app: this.app, message: t(($) => $.originalAttachmentNames.storage.obsidianSyncUnavailable) });
                return;
              }
              // Ask Sync's own filter about every root history can be written to, so a JSON file it would skip is caught
              // here, on this device, instead of silently never reaching the others.
              const roots = [...component.transportRoots, getOriginalNameTransportRoot(this.pluginSettingsComponent.settings.pluginDataFolder)];
              const notCarriedRoot = roots.find((root) => obsidianSyncStatus.doesCarryFile(`${root}/${SYNC_PROBE_FILE_NAME}`) === false);
              if (notCarriedRoot !== undefined) {
                await alert({ app: this.app, message: t(($) => $.originalAttachmentNames.storage.obsidianSyncNotCarried, { path: notCarriedRoot }) });
                return;
              }
            }
            const message = t(($) => isObsidianSync ? $.originalAttachmentNames.storage.obsidianChecklist : $.originalAttachmentNames.storage.externalChecklist);
            if (
              await confirm({
                app: this.app,
                message,
                title: t(($) => $.originalAttachmentNames.storage.setupTitle)
              })
            ) {
              await component.setSyncEnabled(true, { shouldUseObsidianSync: isObsidianSync });
            }
          };
          setting.addButton((button) =>
            button.setButtonText(t(($) => $.originalAttachmentNames.storage.obsidianSync)).onClick(convertAsyncToSync(() =>
              run(async () => {
                await setup(true);
              })
            ))
          );
          setting.addButton((button) =>
            button.setButtonText(t(($) => $.originalAttachmentNames.storage.externalSync)).onClick(convertAsyncToSync(() =>
              run(async () => {
                await setup(false);
              })
            ))
          );
          setting.addButton((button) => {
            disableButton = button;
            button.setButtonText(t(($) => $.originalAttachmentNames.storage.disable)).onClick(convertAsyncToSync(() =>
              run(async () => {
                await component.setSyncEnabled(false);
              })
            ));
          });
          setting.addButton((button) =>
            button.setButtonText(t(($) => $.originalAttachmentNames.storage.apply)).onClick(convertAsyncToSync(() =>
              run(async () => {
                const folder = this.pluginSettingsComponent.settings.pluginDataFolder;
                if (
                  !await isPluginOwnedDataFolder(this.app.vault.adapter, folder)
                  && !await confirm({
                    app: this.app,
                    message: t(($) => $.originalAttachmentNames.storage.sharedFolder, { folder, subfolder: PLUGIN_DATA_SUBFOLDER_NAME }),
                    title: t(($) => $.originalAttachmentNames.storage.sharedFolderTitle)
                  })
                ) {
                  return;
                }
                await component.relocate(folder);
              })
            ))
          );
          updateDescription();
        }
      })
    ];
  }
}

/**
 * Explains the entry syntax every vault path list shares, which is `@mnaoumov/obsidian-lib`'s `PathSettings`.
 *
 * One helper for the four lists, so their descriptions cannot drift from each other or from what the library matches.
 *
 * @param f - The description fragment to append to.
 */
function appendPathEntrySyntax(f: DocumentFragment): void {
  f.appendText(t(($) => $.pluginSettingsTab.pathEntrySyntax.intro));
  f.createEl('br');
  appendCodeBlock(f, 'Archive/Old');
  f.appendText(' ');
  f.appendText(t(($) => $.pluginSettingsTab.pathEntrySyntax.plainPath));
  f.createEl('br');
  appendCodeBlock(f, '*.pdf');
  f.appendText(', ');
  appendCodeBlock(f, 'Archive/**/*.png');
  f.appendText(', ');
  appendCodeBlock(f, '*_files/');
  f.appendText(' ');
  f.appendText(t(($) => $.pluginSettingsTab.pathEntrySyntax.glob));
  f.createEl('br');
  appendCodeBlock(f, String.raw`/^Archive\/\d{4}\//`);
  f.appendText(' ');
  f.appendText(t(($) => $.pluginSettingsTab.pathEntrySyntax.regularExpression));
  f.createEl('br');
  f.appendText(t(($) => $.pluginSettingsTab.pathEntrySyntax.escape));
}

/**
 * Marks a token, written with its braces, for {@link createFragmentWithCodeBlocks}.
 *
 * A message names a token by putting it in braces, which i18next would read as its own interpolation. Passing the
 * token back as the value of that interpolation keeps the message one translatable unit and renders the token as
 * code wherever a translation puts it.
 *
 * @param tokenName - The token's name, without braces.
 * @returns The token in braces, marked as a code block.
 */
function asTokenCodeBlock(tokenName: string): string {
  return asCodeBlock(`{{${tokenName}}}`);
}

/**
 * The `Collect attachments` command family, as a code span placed in a translated sentence.
 *
 * @returns The placeholder node builder.
 */
function collectAttachmentsCommandNode(): TranslationNode {
  return codeNode(t(($) => $.pluginSettingsTab.attachmentOperationTemplates.collect.name));
}

/**
 * The `Collected attachment file name` setting, as a code span placed in a translated sentence.
 *
 * @returns The placeholder node builder.
 */
function collectedAttachmentFileNameSettingNode(): TranslationNode {
  return codeNode(t(($) => $.pluginSettingsTab.collectedAttachmentFileName.name));
}

function generateJpegQualityOptions(): Record<string, string> {
  const MAX_QUALITY = 20;
  const ans: Record<string, string> = {};
  for (let index = 1; index <= MAX_QUALITY; index++) {
    const valueString = (index / MAX_QUALITY).toFixed(JPEG_QUALITY_PRECISION);
    ans[valueString] = valueString;
  }

  return ans;
}

/**
 * The text shown for an advice kind.
 *
 * @param advice - The advice.
 * @returns The text, with its token marked by {@link asCodeBlock}, or `null` when there is nothing to say.
 */
function getAdviceText(advice: OriginalNameSyncAdvice): null | string {
  const originalAttachmentFileName = asTokenCodeBlock('originalAttachmentFileName');
  const texts: Record<OriginalNameSyncAdvice, () => null | string> = {
    [OriginalNameSyncAdvice.EnabledWithoutObsidianSync]: () => t(($) => $.originalAttachmentNames.storage.advice.enabledWithoutObsidianSync),
    [OriginalNameSyncAdvice.None]: () => null,
    [OriginalNameSyncAdvice.NotNeeded]: () => t(($) => $.originalAttachmentNames.storage.advice.notNeeded, { originalAttachmentFileName }),
    [OriginalNameSyncAdvice.ObsidianSyncNotConnected]: () => t(($) => $.originalAttachmentNames.storage.advice.obsidianSyncNotConnected, { originalAttachmentFileName }),
    [OriginalNameSyncAdvice.Recommended]: () => t(($) => $.originalAttachmentNames.storage.advice.recommended, { originalAttachmentFileName })
  };
  return texts[advice]();
}

function handleWhitespace(text: TextComponent): void {
  text.inputEl.addEventListener('input', () => {
    const start = text.inputEl.selectionStart ?? 0;
    const end = text.inputEl.selectionEnd ?? 0;
    text.inputEl.value = showSpaceCharacter(text.inputEl.value);
    text.inputEl.setSelectionRange(start, end);
  });
}

/**
 * The `Rename attachments in current note` command, as a code span placed in a translated sentence.
 *
 * @returns The placeholder node builder.
 */
function renameAttachmentsCommandNode(): TranslationNode {
  return codeNode(t(($) => $.commands.renameAttachmentsCurrentNote));
}

function restoreSpaceCharacter($string: string): string {
  return $string.replaceAll(VISIBLE_SPACE_CHARACTER, ' ');
}

function showSpaceCharacter($string: string): string {
  return $string.replaceAll(' ', () => VISIBLE_SPACE_CHARACTER);
}

/**
 * The link to the token reference, placed in a translated sentence.
 *
 * @returns The placeholder node builder.
 */
function tokensLinkNode(): TranslationNode {
  return linkNode(TOKEN_REFERENCE_DOCUMENTATION_URL, t(($) => $.links.tokens));
}
