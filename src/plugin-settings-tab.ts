import type {
  SettingDefinitionItem,
  SettingDefinitionRender,
  TextComponent
} from 'obsidian';
import type { PluginSuggestionComponent } from 'obsidian-dev-utils/obsidian/components/plugin-suggestion-component';
import type {
  BindOptionsExtended,
  PluginSettingsTabBaseConstructorParams
} from 'obsidian-dev-utils/obsidian/plugin/plugin-settings-tab';
import type { ConditionalKeys } from 'type-fest';

import {
  debounce,
  normalizePath
} from 'obsidian';
import {
  convertAsyncToSync,
  invokeAsyncSafely
} from 'obsidian-dev-utils/async';
import { SuggestedPluginState } from 'obsidian-dev-utils/obsidian/components/plugin-suggestion-component';
import { appendCodeBlock } from 'obsidian-dev-utils/obsidian/html-element';
import { t } from 'obsidian-dev-utils/obsidian/i18n/i18n';
import { confirm } from 'obsidian-dev-utils/obsidian/modals/confirm';
import { PluginSettingsTabBase } from 'obsidian-dev-utils/obsidian/plugin/plugin-settings-tab';

import type { PluginSettingsComponent } from './plugin-settings-component.ts';
import type { PluginSettings } from './plugin-settings.ts';

import {
  AttachmentRenameMode,
  CollectAttachmentUsedByMultipleNotesMode,
  ConvertImagesToJpegMode,
  DefaultImageSizeDimension,
  MoveAttachmentToProperFolderUsedByMultipleNotesMode,
  RenameAttachmentsCreatedByOtherPluginsMode,
  SAMPLE_CUSTOM_TOKENS
} from './plugin-settings.ts';
import { Substitutions } from './substitutions.ts';
import { TOKENIZED_STRING_LANGUAGE } from './tokenized-string-language-component.ts';

const VISIBLE_SPACE_CHARACTER = '␣';
const JPEG_QUALITY_PRECISION = 2;
const REGISTER_CUSTOM_TOKENS_DEBOUNCE_IN_MILLISECONDS = 2000;

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
  readonly pluginSettingsComponent: PluginSettingsComponent;
  readonly pluginSuggestionComponent: PluginSuggestionComponent;
}

export class PluginSettingsTab extends PluginSettingsTabBase<PluginSettings> {
  // Kept so this plugin can leave ITSELF out of the plugin picker; the base class does not expose `plugin`.
  private readonly ownPluginId: string;
  private readonly pluginSettingsComponent2: PluginSettingsComponent;
  private readonly pluginSuggestionComponent: PluginSuggestionComponent;

  public constructor(params: PluginSettingsTabConstructorParams) {
    super(params);
    this.ownPluginId = params.plugin.manifest.id;
    this.pluginSettingsComponent2 = params.pluginSettingsComponent;
    this.pluginSuggestionComponent = params.pluginSuggestionComponent;
  }

  public override hide(): void {
    super.hide();
    this.pluginSettingsComponent2.shouldDebounceCustomTokensValidation = false;
  }

  protected override getSettingDefinitionItems(): SettingDefinitionItem[] {
    return [
      // The suggestion banner has to travel as a ROW: Obsidian renders the declarative definitions and never
      // Calls `display()` once `getSettingDefinitions()` is non-empty, so there is no container to write into
      // Otherwise. The row body is emptied first, leaving the Setting element as a bare host for the banner.
      this.settingEx({
        name: '',
        render: (setting) => {
          setting.settingEl.empty();
          this.pluginSuggestionComponent.renderBanner(setting.settingEl);
        },
        searchable: false,
        visible: () => this.pluginSuggestionComponent.getSuggestedPluginState() !== SuggestedPluginState.Enabled
      }),
      this.settingGroupEx({
        heading: t(($) => $.pluginSettingsTab.groups.core),
        items: this.getCoreItems()
      }),
      {
        desc: t(($) => $.pluginSettingsTab.pages.moveRenames.description),
        items: this.getMoveRenamesItems(),
        name: t(($) => $.pluginSettingsTab.groups.moveRenames),
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
        desc: createFragment((f) => {
          f.appendText(t(($) => $.pluginSettingsTab.markdownUrlFormat.description.part1));
          f.createEl('br');
          f.appendText(t(($) => $.pluginSettingsTab.markdownUrlFormat.description.part2));
          f.appendText(' ');
          f.createEl('a', {
            href: 'https://github.com/mnaoumov/obsidian-custom-attachment-location?tab=readme-ov-file#tokens',
            text: t(($) => $.pluginSettingsTab.markdownUrlFormat.description.part3)
          });
          f.appendText('.');
          f.createEl('br');
          f.appendText(t(($) => $.pluginSettingsTab.markdownUrlFormat.description.part4));
        }),
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
        desc: t(($) => $.pluginSettingsTab.shouldSetLinkDisplayTextToAttachmentFileName.description),
        name: t(($) => $.pluginSettingsTab.shouldSetLinkDisplayTextToAttachmentFileName.name),
        render: (setting) => {
          setting.addToggle((toggle) => {
            this.bind({
              propertyName: 'shouldSetLinkDisplayTextToAttachmentFileName',
              valueComponent: toggle
            });
          });
        }
      }),
      this.settingEx({
        desc: createFragment((f) => {
          f.appendText(t(($) => $.pluginSettingsTab.timeoutInSeconds.description.part1));
          f.createEl('br');
          f.appendText(t(($) => $.pluginSettingsTab.timeoutInSeconds.description.part2));
          f.appendText(' ');
          appendCodeBlock(f, '0');
          f.appendText(' ');
          f.appendText(t(($) => $.pluginSettingsTab.timeoutInSeconds.description.part3));
        }),
        name: t(($) => $.pluginSettingsTab.timeoutInSeconds.name),
        render: (setting) => {
          setting.addNumber((number) => {
            number.setMin(0);
            this.bind({
              propertyName: 'timeoutInSeconds',
              valueComponent: number
            });
          });
        }
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
          setting.addNumber((number) => {
            number.setMin(1);
            this.bind({
              propertyName: 'networkImageDownloadTimeoutInSeconds',
              valueComponent: number
            });
          });
        },
        visible: () => this.pluginSettingsComponent.settings.downloadNetworkImages
      }),
      this.settingEx({
        desc: createFragment((f) => {
          f.appendText(t(($) => $.pluginSettingsTab.shouldRenameCollectedAttachments.description.part1));
          f.appendText(' ');
          appendCodeBlock(f, t(($) => $.pluginSettingsTab.shouldRenameCollectedAttachments.description.part2));
          f.appendText(' ');
          f.appendText(t(($) => $.pluginSettingsTab.shouldRenameCollectedAttachments.description.part3));
          f.appendText(' ');
          appendCodeBlock(f, t(($) => $.pluginSettingsTab.collectedAttachmentFileName.name));
          f.appendText(' ');
          f.appendText(t(($) => $.pluginSettingsTab.shouldRenameCollectedAttachments.description.part4));
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
        desc: createFragment((f) => {
          f.appendText(t(($) => $.pluginSettingsTab.collectedAttachmentFileName.description.part1));
          f.appendText(' ');
          f.createEl('a', {
            href: 'https://github.com/mnaoumov/obsidian-custom-attachment-location?tab=readme-ov-file#tokens',
            text: t(($) => $.pluginSettingsTab.collectedAttachmentFileName.description.part2)
          });
          f.appendText('.');
          f.createEl('br');
          f.appendText(t(($) => $.pluginSettingsTab.collectedAttachmentFileName.description.part3));
        }),
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
        desc: createFragment((f) => {
          f.appendText(t(($) => $.pluginSettingsTab.collectAttachmentUsedByMultipleNotesMode.description.part1));
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
      })
    ];
  }

  private getCoreItems(): SettingDefinitionRender[] {
    return [
      this.settingEx({
        desc: createFragment((f) => {
          f.appendText(t(($) => $.pluginSettingsTab.locationForNewAttachments.description.part1));
          f.appendText(' ');
          appendCodeBlock(f, '.');
          f.appendText(' ');
          f.appendText(t(($) => $.pluginSettingsTab.locationForNewAttachments.description.part2));
          f.createEl('br');
          f.appendText(t(($) => $.pluginSettingsTab.locationForNewAttachments.description.part3));
          f.appendText(' ');
          f.createEl('a', {
            href: 'https://github.com/mnaoumov/obsidian-custom-attachment-location?tab=readme-ov-file#tokens',
            text: t(($) => $.pluginSettingsTab.locationForNewAttachments.description.part4)
          });
          f.createEl('br');
          f.appendText(t(($) => $.pluginSettingsTab.locationForNewAttachments.description.part5));
          f.appendText(' ');
          appendCodeBlock(f, '.attachments');
          f.appendText(' ');
          f.appendText(t(($) => $.pluginSettingsTab.locationForNewAttachments.description.part6));
          f.appendText(' ');
          f.createEl('a', { href: 'https://community.obsidian.md/plugins/unhide', text: 'Unhide' });
          f.appendText(' ');
          f.appendText(t(($) => $.pluginSettingsTab.locationForNewAttachments.description.part7));
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
        }
      }),
      this.settingEx({
        desc: createFragment((f) => {
          f.appendText(t(($) => $.pluginSettingsTab.generatedAttachmentFileName.description.part1));
          f.appendText(' ');
          f.createEl('a', {
            href: 'https://github.com/mnaoumov/obsidian-custom-attachment-location?tab=readme-ov-file#tokens',
            text: t(($) => $.pluginSettingsTab.generatedAttachmentFileName.description.part2)
          });
          f.appendText('.');
        }),
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
      })
    ];
  }

  private getCustomTokensItems(): SettingDefinitionRender[] {
    return [
      this.settingEx({
        desc: createFragment((f) => {
          f.appendText(t(($) => $.pluginSettingsTab.customTokens.description.part1));
          f.createEl('br');
          f.appendText(t(($) => $.pluginSettingsTab.customTokens.description.part2));
          f.appendText(' ');
          f.createEl('a', {
            href: 'https://github.com/mnaoumov/obsidian-custom-attachment-location?tab=readme-ov-file#custom-tokens',
            text: t(($) => $.pluginSettingsTab.customTokens.description.part3)
          });
          f.appendText(' ');
          f.appendText(t(($) => $.pluginSettingsTab.customTokens.description.part4));
          f.createEl('br');
          f.appendText(t(($) => $.pluginSettingsTab.customTokens.description.part5));
        }),
        name: t(($) => $.pluginSettingsTab.customTokens.name),
        render: (setting) => {
          // Render-time setup: the builder must stay pure, because Obsidian calls it at plugin load to
          // Index the settings for search. `hide()` clears the flag again.
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
              if (this.pluginSettingsComponent.settings.customTokensStr === SAMPLE_CUSTOM_TOKENS) {
                return;
              }

              if (
                this.pluginSettingsComponent.settings.customTokensStr !== '' && !await confirm({
                  app: this.app,
                  cancelButtonText: t(($) => $.obsidianDevUtils.buttons.cancel),
                  message: t(($) => $.pluginSettingsTab.resetToSampleCustomTokens.message),
                  okButtonText: t(($) => $.obsidianDevUtils.buttons.ok),
                  title: t(($) => $.pluginSettingsTab.resetToSampleCustomTokens.title)
                })
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
        desc: createFragment((f) => {
          f.appendText(t(($) => $.pluginSettingsTab.defaultImageSize.description.part1));
          f.createEl('br');
          f.appendText(t(($) => $.pluginSettingsTab.defaultImageSize.description.part2));
          f.appendText(' (');
          appendCodeBlock(f, '300px');
          f.appendText(') ');
          f.appendText(t(($) => $.pluginSettingsTab.defaultImageSize.description.part3));
          f.appendText(' (');
          appendCodeBlock(f, '50%');
          f.appendText(').');
          f.createEl('br');
          f.appendText(t(($) => $.pluginSettingsTab.defaultImageSize.description.part4));
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
              dropdown.selectEl.addClass('default-image-size-dimension-setting-control');
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
          f.appendText(t(($) => $.pluginSettingsTab.convertImagesToJpegMode.description.part1));
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
        desc: createFragment((f) => {
          f.appendText(t(($) => $.pluginSettingsTab.shouldPreserveImageMetadata.description.part1));
          f.createEl('br');
          f.appendText(t(($) => $.pluginSettingsTab.shouldPreserveImageMetadata.description.part2));
          f.createEl('br');
          f.appendText(t(($) => $.pluginSettingsTab.shouldPreserveImageMetadata.description.part3));
        }),
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
        desc: createFragment((f) => {
          f.appendText(t(($) => $.pluginSettingsTab.duplicateNameSeparator.description.part1));
          f.createEl('br');
          f.appendText(t(($) => $.pluginSettingsTab.duplicateNameSeparator.description.part2));
          f.appendText(' ');
          appendCodeBlock(f, 'existingFile.pdf');
          f.appendText(t(($) => $.pluginSettingsTab.duplicateNameSeparator.description.part3));
          f.appendText(' ');
          appendCodeBlock(f, 'existingFile 1.pdf');
          f.appendText(', ');
          appendCodeBlock(f, 'existingFile 2.pdf');
          f.appendText(t(($) => $.pluginSettingsTab.duplicateNameSeparator.description.part4));
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
        desc: createFragment((f) => {
          f.appendText(t(($) => $.pluginSettingsTab.attachmentRenameMode.description.part1));
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
        desc: createFragment((f) => {
          f.appendText(t(($) => $.pluginSettingsTab.renameAttachmentsCreatedByOtherPluginsMode.description.part1));
          f.createEl('br');
          f.appendText(t(($) => $.pluginSettingsTab.renameAttachmentsCreatedByOtherPluginsMode.description.part2));
          f.createEl('br');
          f.appendText(t(($) => $.pluginSettingsTab.renameAttachmentsCreatedByOtherPluginsMode.description.part3));
          f.createEl('br');
          appendCodeBlock(f, t(($) => $.pluginSettings.renameAttachmentsCreatedByOtherPluginsMode.none.displayText));
          f.appendText(' - ');
          f.appendText(t(($) => $.pluginSettings.renameAttachmentsCreatedByOtherPluginsMode.none.description));
          f.createEl('br');
          appendCodeBlock(f, t(($) => $.pluginSettings.renameAttachmentsCreatedByOtherPluginsMode.all.displayText));
          f.appendText(' - ');
          f.appendText(t(($) => $.pluginSettings.renameAttachmentsCreatedByOtherPluginsMode.all.description));
          f.createEl('br');
          appendCodeBlock(f, t(($) => $.pluginSettings.renameAttachmentsCreatedByOtherPluginsMode.onlyListedPlugins.displayText));
          f.appendText(' - ');
          f.appendText(t(($) => $.pluginSettings.renameAttachmentsCreatedByOtherPluginsMode.onlyListedPlugins.description));
          f.createEl('br');
          appendCodeBlock(f, t(($) => $.pluginSettings.renameAttachmentsCreatedByOtherPluginsMode.allExceptListedPlugins.displayText));
          f.appendText(' - ');
          f.appendText(t(($) => $.pluginSettings.renameAttachmentsCreatedByOtherPluginsMode.allExceptListedPlugins.description));
          f.createEl('br');
          f.appendText(t(($) => $.pluginSettingsTab.renameAttachmentsCreatedByOtherPluginsMode.description.part4));
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
        desc: createFragment((f) => {
          f.appendText(t(($) => $.pluginSettingsTab.otherPluginIdsForAttachmentRename.description.part1));
          f.createEl('br');
          f.appendText(t(($) => $.pluginSettingsTab.otherPluginIdsForAttachmentRename.description.part2));
        }),
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
          f.appendText(t(($) => $.pluginSettingsTab.renamedAttachmentFileName.description.part1));
          f.appendText(' ');
          f.createEl('a', {
            href: 'https://github.com/mnaoumov/obsidian-custom-attachment-location?tab=readme-ov-file#tokens',
            text: t(($) => $.pluginSettingsTab.renamedAttachmentFileName.description.part2)
          });
          f.appendText('.');
          f.createEl('br');
          f.appendText(t(($) => $.pluginSettingsTab.renamedAttachmentFileName.description.part3));
        }),
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
      }),
      this.settingEx({
        desc: createFragment((f) => {
          f.appendText(t(($) => $.pluginSettingsTab.moveAttachmentToProperFolderUsedByMultipleNotesMode.description.part1));
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

  private getPathItems(): SettingDefinitionRender[] {
    return [
      this.settingEx({
        desc: createFragment((f) => {
          f.appendText(t(($) => $.pluginSettingsTab.attachmentUnitFolderPaths.description.part1));
          f.appendText(' ');
          appendCodeBlock(f, t(($) => $.pluginSettingsTab.attachmentUnitFolderPaths.description.part2));
          f.appendText(' ');
          f.appendText(t(($) => $.pluginSettingsTab.attachmentUnitFolderPaths.description.part3));
          f.createEl('br');
          f.appendText(t(($) => $.pluginSettingsTab.attachmentUnitFolderPaths.description.part4));
          f.createEl('br');
          f.appendText(t(($) => $.pluginSettingsTab.attachmentUnitFolderPaths.description.part5));
          f.createEl('br');
          f.appendText(t(($) => $.pluginSettingsTab.attachmentUnitFolderPaths.description.part6));
          f.appendText(' ');
          appendCodeBlock(f, t(($) => $.regularExpression));
          f.appendText('.');
          f.createEl('br');
          f.appendText(t(($) => $.pluginSettingsTab.attachmentUnitFolderPaths.description.part7));
          f.createEl('br');
          f.appendText(t(($) => $.pluginSettingsTab.attachmentUnitFolderPaths.description.part8));
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
        desc: createFragment((f) => {
          f.appendText(t(($) => $.pluginSettingsTab.excludePathsFromAttachmentCollecting.description.part1));
          f.appendText(' ');
          appendCodeBlock(f, t(($) => $.pluginSettingsTab.excludePathsFromAttachmentCollecting.description.part2));
          f.appendText(' ');
          f.appendText(t(($) => $.pluginSettingsTab.excludePathsFromAttachmentCollecting.description.part3));
          f.createEl('br');
          f.appendText(t(($) => $.pluginSettingsTab.excludePathsFromAttachmentCollecting.description.part4));
          f.createEl('br');
          f.appendText(t(($) => $.pluginSettingsTab.excludePathsFromAttachmentCollecting.description.part5));
          f.appendText(' ');
          appendCodeBlock(f, t(($) => $.regularExpression));
          f.appendText('.');
          f.createEl('br');
          f.appendText(t(($) => $.pluginSettingsTab.excludePathsFromAttachmentCollecting.description.part6));
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
        desc: createFragment((f) => {
          f.appendText(t(($) => $.pluginSettingsTab.excludePathsFromMultipleNotesCheck.description.part1));
          f.appendText(' ');
          appendCodeBlock(f, t(($) => $.pluginSettingsTab.excludePathsFromMultipleNotesCheck.description.part2));
          f.appendText(' ');
          f.appendText(t(($) => $.pluginSettingsTab.excludePathsFromMultipleNotesCheck.description.part3));
          f.appendText(' ');
          appendCodeBlock(f, t(($) => $.pluginSettingsTab.excludePathsFromMultipleNotesCheck.description.part4));
          f.appendText(' ');
          f.appendText(t(($) => $.pluginSettingsTab.excludePathsFromMultipleNotesCheck.description.part5));
          f.createEl('br');
          f.appendText(t(($) => $.pluginSettingsTab.excludePathsFromMultipleNotesCheck.description.part6));
          f.createEl('br');
          f.appendText(t(($) => $.pluginSettingsTab.excludePathsFromMultipleNotesCheck.description.part7));
          f.appendText(' ');
          appendCodeBlock(f, t(($) => $.regularExpression));
          f.appendText('.');
          f.createEl('br');
          f.appendText(t(($) => $.pluginSettingsTab.excludePathsFromMultipleNotesCheck.description.part8));
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
        desc: createFragment((f) => {
          f.appendText(t(($) => $.pluginSettingsTab.specialCharacters.description.part1));
          f.createEl('br');
          f.appendText(t(($) => $.pluginSettingsTab.specialCharacters.description.part2));
        }),
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
        desc: createFragment((f) => {
          f.appendText(t(($) => $.pluginSettingsTab.specialCharactersReplacement.description.part1));
          f.createEl('br');
          f.appendText(t(($) => $.pluginSettingsTab.specialCharactersReplacement.description.part2));
        }),
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

function handleWhitespace(text: TextComponent): void {
  text.inputEl.addEventListener('input', () => {
    const start = text.inputEl.selectionStart ?? 0;
    const end = text.inputEl.selectionEnd ?? 0;
    text.inputEl.value = showSpaceCharacter(text.inputEl.value);
    text.inputEl.setSelectionRange(start, end);
  });
}

function restoreSpaceCharacter($string: string): string {
  return $string.replaceAll(VISIBLE_SPACE_CHARACTER, ' ');
}

function showSpaceCharacter($string: string): string {
  return $string.replaceAll(' ', () => VISIBLE_SPACE_CHARACTER);
}
