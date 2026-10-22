/**
 * @file
 *
 * A confirmation dialog the user can set aside to go and look at what it is asking about.
 *
 * It takes exactly what `confirm` from `@mnaoumov/obsidian-lib/modals/confirm` takes, and draws the
 * same dialog with the same classes, but opens it through {@link MinimizableModal}: a minimize button sits
 * beside the close button, and a floating bar restores it. While it is minimized the app is peek-only, so
 * nothing new can be started behind a pending confirmation.
 *
 * Clicking a link in the message minimizes it too. The dialog covers the workspace, so a file opened from
 * one of its links would otherwise open BEHIND it, where the user cannot see it (#87).
 */

import type { ConfirmParams } from '@mnaoumov/obsidian-lib/modals/confirm';
import type { ModalBaseConstructorParams } from '@mnaoumov/obsidian-lib/modals/modal';
import type { PromiseResolve } from '@mnaoumov/typescript-lib/async';

import { CssClass } from '@mnaoumov/obsidian-lib/css-class';
import { t } from '@mnaoumov/obsidian-lib/i18n/i18n';
import { MinimizableModal } from '@mnaoumov/obsidian-lib/modals/minimizable-modal';
import {
  ModalBase,
  showModal
} from '@mnaoumov/obsidian-lib/modals/modal';
import { ButtonComponent } from 'obsidian';

/**
 * Parameters for {@link confirmMinimizable}: exactly what `confirm` takes.
 */
export type ConfirmMinimizableParams = ConfirmParams;

type MinimizableConfirmModalConstructorParams = ConfirmMinimizableParams & ModalBaseConstructorParams<boolean>;

class MinimizableConfirmModal extends ModalBase<boolean> {
  private readonly cancelButtonText: string;
  private isConfirmed = false;
  private readonly message: DocumentFragment | string;
  private readonly okButtonText: string;
  private readonly title: DocumentFragment | string;

  public constructor(params: MinimizableConfirmModalConstructorParams) {
    super(params);
    this.addCssClasses(CssClass.ConfirmModal);
    this.cancelButtonText = params.cancelButtonText ?? t(($) => $.obsidianLib.buttons.cancel);
    this.message = params.message;
    this.okButtonText = params.okButtonText ?? t(($) => $.obsidianLib.buttons.ok);
    this.title = params.title ?? '';
  }

  public override onClose(): void {
    this.promiseResolve(this.isConfirmed);
  }

  public override onOpen(): void {
    this.titleEl.setText(this.title);
    this.contentEl.createEl('p', { text: this.message });

    const okButton = new ButtonComponent(this.contentEl);
    okButton.setButtonText(this.okButtonText);
    okButton.setCta();
    okButton.onClick(() => {
      this.isConfirmed = true;
      this.close();
    });
    okButton.setClass(CssClass.OkButton);

    const cancelButton = new ButtonComponent(this.contentEl);
    cancelButton.setButtonText(this.cancelButtonText);
    cancelButton.onClick(() => {
      this.close();
    });
    cancelButton.setClass(CssClass.CancelButton);
  }
}

/**
 * Displays a minimizable confirmation dialog.
 *
 * @param params - The parameters for the dialog, the same as `confirm` takes.
 * @returns A {@link Promise} that resolves with whether the OK button was clicked.
 */
// eslint-disable-next-line unicorn/consistent-boolean-name -- Named after `confirm`, whose `boolean` answer it stands in for.
export async function confirmMinimizable(params: ConfirmMinimizableParams): Promise<boolean> {
  return await showModal<boolean>((promiseResolve: PromiseResolve<boolean>) => {
    const minimizableModal = new MinimizableModal(
      new MinimizableConfirmModal({
        ...params,
        promiseResolve
      })
    );

    minimizableModal.modal.contentEl.addEventListener('click', ($event) => {
      if ($event.target instanceof Element && $event.target.closest('a')) {
        minimizableModal.minimize();
      }
    });

    return minimizableModal.modal;
  });
}
