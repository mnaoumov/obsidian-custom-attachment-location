/**
 * @file
 *
 * The confirmation behind `Prune original attachment names`.
 *
 * A record outlives its file when the file is deleted or moved outside Obsidian, where no vault event reaches this
 * plugin. Pruning removes exactly those, after showing which. `Forget all` sits in the same dialog, behind a second
 * confirmation, because it throws away every name that is still true.
 */

import type { PromiseResolve } from '@mnaoumov/typescript-lib/async';
import type { App } from 'obsidian';

import { appendCodeBlock } from '@mnaoumov/obsidian-lib/html-element';
import { t } from '@mnaoumov/obsidian-lib/i18n/i18n';
import { confirm } from '@mnaoumov/obsidian-lib/modals/confirm';
import {
  ModalBase,
  showModal
} from '@mnaoumov/obsidian-lib/modals/modal';
import { convertAsyncToSync } from '@mnaoumov/typescript-lib/async';
import { ButtonComponent } from 'obsidian';

import type { OriginalAttachmentNamesComponent } from '../original-attachment-names-component.ts';

/**
 * What the user chose in the prune dialog.
 */
export enum PruneOriginalAttachmentNamesChoice {
  /**
   * Nothing: the dialog was cancelled.
   */
  Cancel = 'Cancel',

  /**
   * Every record, after a second confirmation.
   */
  ForgetAll = 'ForgetAll',

  /**
   * The records whose path no longer exists.
   */
  Prune = 'Prune'
}

/**
 * Parameters for {@link showPruneOriginalAttachmentNamesModal}.
 */
export interface ShowPruneOriginalAttachmentNamesModalParams {
  /**
   * An Obsidian app instance.
   */
  readonly app: App;

  /**
   * The store to prune.
   */
  readonly originalAttachmentNamesComponent: OriginalAttachmentNamesComponent;
}

interface PruneOriginalAttachmentNamesModalConstructorParams extends ShowPruneOriginalAttachmentNamesModalParams {
  readonly promiseResolve: PromiseResolve<PruneOriginalAttachmentNamesChoice>;
}

class PruneOriginalAttachmentNamesModal extends ModalBase<PruneOriginalAttachmentNamesChoice> {
  private choice = PruneOriginalAttachmentNamesChoice.Cancel;
  private readonly originalAttachmentNamesComponent: OriginalAttachmentNamesComponent;

  public constructor(params: PruneOriginalAttachmentNamesModalConstructorParams) {
    super(params);
    this.originalAttachmentNamesComponent = params.originalAttachmentNamesComponent;
  }

  public override onClose(): void {
    this.promiseResolve(this.choice);
  }

  public override onOpen(): void {
    this.titleEl.setText(t(($) => $.originalAttachmentNames.pruneModal.title));

    const staleRecords = this.originalAttachmentNamesComponent.getRecords().filter((record) => record.isMissing);
    if (staleRecords.length === 0) {
      this.contentEl.createEl('p', { text: t(($) => $.originalAttachmentNames.pruneModal.noStale) });
    } else {
      this.contentEl.createEl('p', { text: t(($) => $.originalAttachmentNames.pruneModal.staleCount, { count: staleRecords.length }) });
      const listEl = this.contentEl.createEl('ul');
      for (const record of staleRecords) {
        listEl.createEl('li', { text: `${record.path} → ${record.originalFileName}` });
      }
    }

    const buttonsEl = this.contentEl.createDiv('modal-button-container');

    if (staleRecords.length > 0) {
      new ButtonComponent(buttonsEl)
        .setButtonText(t(($) => $.originalAttachmentNames.pruneModal.prune))
        .setCta()
        .onClick(() => {
          this.choice = PruneOriginalAttachmentNamesChoice.Prune;
          this.close();
        });
    }

    new ButtonComponent(buttonsEl)
      .setButtonText(t(($) => $.originalAttachmentNames.pruneModal.forgetAll))
      .setDestructive()
      .setDisabled(this.originalAttachmentNamesComponent.size === 0)
      .onClick(convertAsyncToSync(async () => {
        if (!await isForgetAllConfirmed(this.app, this.originalAttachmentNamesComponent.size)) {
          return;
        }

        this.choice = PruneOriginalAttachmentNamesChoice.ForgetAll;
        this.close();
      }));

    new ButtonComponent(buttonsEl)
      .setButtonText(t(($) => $.obsidianLib.buttons.cancel))
      .onClick(this.close.bind(this));
  }
}

/**
 * Asks whether to forget every record, saying what that does to `{{originalAttachmentFileName}}`.
 *
 * @param app - The Obsidian app instance.
 * @param count - How many records there are.
 * @returns Whether the user confirmed.
 */
export async function isForgetAllConfirmed(app: App, count: number): Promise<boolean> {
  return await confirm({
    app,
    message: createFragment((f) => {
      f.appendText(t(($) => $.originalAttachmentNames.pruneModal.forgetAllConfirm.part1, { count }));
      f.appendText(' ');
      appendCodeBlock(f, '{{originalAttachmentFileName}}');
      f.appendText(' ');
      f.appendText(t(($) => $.originalAttachmentNames.pruneModal.forgetAllConfirm.part2));
    }),
    okButtonText: t(($) => $.originalAttachmentNames.pruneModal.forgetAll),
    title: t(($) => $.originalAttachmentNames.pruneModal.forgetAllConfirm.title)
  });
}

/**
 * Shows which records pruning would remove, and lets the user prune them or forget every record.
 *
 * @param params - The store and the app.
 * @returns What the user chose. Nothing is removed here; the caller acts on the choice.
 */
export async function showPruneOriginalAttachmentNamesModal(params: ShowPruneOriginalAttachmentNamesModalParams): Promise<PruneOriginalAttachmentNamesChoice> {
  return await showModal<PruneOriginalAttachmentNamesChoice>((promiseResolve) =>
    new PruneOriginalAttachmentNamesModal({
      ...params,
      promiseResolve
    })
  );
}
