import type { App } from 'obsidian';
import type { PromiseResolve } from 'obsidian-dev-utils/async';
import type { NoPriorityWinnerReason } from 'obsidian-dev-utils/obsidian/note-priority';

import {
  Modal,
  Setting
} from 'obsidian';
import { invokeAsyncSafely } from 'obsidian-dev-utils/async';
import {
  createElAsync,
  createFragmentAsync
} from 'obsidian-dev-utils/html-element';
import { t } from 'obsidian-dev-utils/obsidian/i18n/i18n';
import { renderInternalLink } from 'obsidian-dev-utils/obsidian/markdown';

import { ADVANCED_RENAME_AND_DELETE_HANDLER_PLUGIN_NAME } from '../advanced-rename-and-delete-handler.ts';
import { CollectAttachmentUsedByMultipleNotesMode } from '../plugin-settings.ts';

interface CollectAttachmentUsedByMultipleNotesModalConstructorParams {
  readonly app: App;
  readonly attachmentPath: string;
  readonly backlinks: string[];
  readonly isCancelMode: boolean;
  readonly noPriorityWinnerReason: NoPriorityWinnerReason | null;
  readonly resolve: PromiseResolve<CollectAttachmentUsedByMultipleNotesModalResult>;
}

interface CollectAttachmentUsedByMultipleNotesModalResult {
  readonly mode: CollectAttachmentUsedByMultipleNotesMode;
  readonly shouldUseSameActionForOtherProblematicAttachments: boolean;
}

interface SelectModeParams {
  readonly app: App;
  readonly attachmentPath: string;
  readonly backlinks: string[];
  readonly isCancelMode?: boolean;

  /**
   * Why the note-priority list named no owner, or `null` when it did name one (and something else
   * stopped the move). Shown to the user as the real reason the attachment stayed put.
   */
  readonly noPriorityWinnerReason?: NoPriorityWinnerReason | null;
}

class CollectAttachmentUsedByMultipleNotesModal extends Modal {
  private readonly attachmentPath: string;
  private readonly backlinks: string[];
  private readonly isCancelMode: boolean;
  private isSelected = false;
  private readonly noPriorityWinnerReason: NoPriorityWinnerReason | null;
  private readonly resolve: PromiseResolve<CollectAttachmentUsedByMultipleNotesModalResult>;

  public constructor(params: CollectAttachmentUsedByMultipleNotesModalConstructorParams) {
    super(params.app);
    this.attachmentPath = params.attachmentPath;
    this.backlinks = params.backlinks;
    this.isCancelMode = params.isCancelMode;
    this.noPriorityWinnerReason = params.noPriorityWinnerReason;
    this.resolve = params.resolve;
  }

  public override onClose(): void {
    if (!this.isSelected) {
      this.select(CollectAttachmentUsedByMultipleNotesMode.Cancel, false);
    }
  }

  public override onOpen(): void {
    super.onOpen();
    invokeAsyncSafely(() => this.onOpenAsync());
  }

  /**
   * States the real reason the attachment stayed put: the note-priority list did not name an owner.
   *
   * Without this the modal only reports that several notes reference the attachment, which is the
   * symptom rather than the cause — the user cannot tell a priority list that was never configured
   * from one that simply did not match, or from a tie.
   */
  private appendNoPriorityWinnerExplanation(): void {
    if (this.noPriorityWinnerReason === null) {
      return;
    }

    const reason = this.noPriorityWinnerReason;
    this.contentEl.createEl('p', {
      cls: 'custom-attachment-location-no-priority-winner-reason',
      text: t(($) => $.collectAttachmentUsedByMultipleNotesModal.noPriorityWinnerReason[reason], {
        // Qualified with the owning plugin since 12.0.0: the setting lives in Advanced Rename and Delete
        // Handler now, so naming it alone would send the user looking through this plugin's tab for a row
        // That is not there. An arrow rather than a possessive, which reads the same in every locale.
        settingName: `${ADVANCED_RENAME_AND_DELETE_HANDLER_PLUGIN_NAME} → ${t(($) => $.pluginSettingsTab.notePriorities.name)}`
      })
    });
  }

  private async onOpenAsync(): Promise<void> {
    super.onOpen();
    new Setting(this.contentEl)
      .setName(t(($) => $.collectAttachmentUsedByMultipleNotesModal.heading))
      .setHeading();

    this.contentEl.append(
      await createFragmentAsync(async (f) => {
        f.appendText(t(($) => $.collectAttachmentUsedByMultipleNotesModal.content.part1));
        f.appendText(' ');
        f.append(
          await renderInternalLink({
            app: this.app,
            pathOrAbstractFile: this.attachmentPath
          })
        );
        f.appendText(' ');
        f.appendText(t(($) => $.collectAttachmentUsedByMultipleNotesModal.content.part2));
        f.append(
          await createElAsync('ul', {}, async (ul) => {
            for (const backlink of this.backlinks) {
              ul.append(
                await createElAsync('li', {}, async (li) => {
                  li.append(
                    await renderInternalLink({
                      app: this.app,
                      pathOrAbstractFile: backlink
                    })
                  );
                })
              );
            }
          })
        );
      })
    );

    this.appendNoPriorityWinnerExplanation();

    let shouldUseSameActionForOtherProblematicAttachments = false;

    if (!this.isCancelMode) {
      new Setting(this.contentEl)
        .setName(t(($) => $.collectAttachmentUsedByMultipleNotesModal.shouldUseSameActionForOtherProblematicAttachmentsToggle))
        .addToggle((toggle) => {
          toggle.setValue(false);
          toggle.onChange((value) => {
            shouldUseSameActionForOtherProblematicAttachments = value;
          });
        });
    }

    const buttonsSetting = new Setting(this.contentEl);
    if (!this.isCancelMode) {
      buttonsSetting
        .addButton((button) => {
          button.setButtonText(t(($) => $.buttons.skip));
          button.onClick(() => {
            this.select(CollectAttachmentUsedByMultipleNotesMode.Skip, shouldUseSameActionForOtherProblematicAttachments);
          });
        })
        .addButton((button) => {
          button.setButtonText(t(($) => $.buttons.move));
          button.onClick(() => {
            this.select(CollectAttachmentUsedByMultipleNotesMode.Move, shouldUseSameActionForOtherProblematicAttachments);
          });
        })
        .addButton((button) => {
          button.setButtonText(t(($) => $.buttons.copy));
          button.onClick(() => {
            this.select(CollectAttachmentUsedByMultipleNotesMode.Copy, shouldUseSameActionForOtherProblematicAttachments);
          });
        });
    }

    buttonsSetting
      .addButton((button) => {
        button.setButtonText(t(($) => $.obsidianDevUtils.buttons.cancel));
        button.onClick(() => {
          this.select(CollectAttachmentUsedByMultipleNotesMode.Cancel, shouldUseSameActionForOtherProblematicAttachments);
        });
      });
  }

  private select(mode: CollectAttachmentUsedByMultipleNotesMode, shouldUseSameActionForOtherProblematicAttachments: boolean): void {
    this.isSelected = true;
    this.resolve({ mode, shouldUseSameActionForOtherProblematicAttachments });
    this.close();
  }
}

export function selectMode(params: SelectModeParams): Promise<CollectAttachmentUsedByMultipleNotesModalResult> {
  const {
    app,
    attachmentPath,
    backlinks,
    isCancelMode,
    noPriorityWinnerReason
  } = params;
  return new Promise((resolve) => {
    const modal = new CollectAttachmentUsedByMultipleNotesModal({
      app,
      attachmentPath,
      backlinks,
      isCancelMode: isCancelMode ?? false,
      noPriorityWinnerReason: noPriorityWinnerReason ?? null,
      resolve
    });
    modal.open();
  });
}
