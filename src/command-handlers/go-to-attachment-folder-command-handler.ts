import type {
  App,
  TAbstractFile,
  TFile
} from 'obsidian';
import type { PluginNoticeComponent } from 'obsidian-dev-utils/obsidian/components/plugin-notice-component';

import { InternalPluginName } from '@obsidian-typings/obsidian-public-latest/implementations';
import { ButtonComponent } from 'obsidian';
import { invokeAsyncSafely } from 'obsidian-dev-utils/async';
import { DUMMY_PATH } from 'obsidian-dev-utils/obsidian/attachment-path';
import { FileCommandHandler } from 'obsidian-dev-utils/obsidian/command-handlers/file-command-handler';
import { appendCodeBlock } from 'obsidian-dev-utils/obsidian/html-element';
import { t } from 'obsidian-dev-utils/obsidian/i18n/i18n';
import { createFolderSafe } from 'obsidian-dev-utils/obsidian/vault';

import type { AttachmentPathManager } from '../attachment-path-manager.ts';
import type { PluginSettingsComponent } from '../plugin-settings-component.ts';

import { ActionContext } from '../token-evaluator-context.ts';

interface GoToAttachmentFolderCommandHandlerConstructorParams {
  readonly app: App;
  readonly attachmentPathManager: AttachmentPathManager;
  readonly pluginNoticeComponent: PluginNoticeComponent;
  readonly pluginSettingsComponent: PluginSettingsComponent;
}

/**
 * Reveals the folder the active note's attachments are saved into.
 *
 * The folder is resolved through the same template the plugin saves attachments with, not by guessing
 * at a literal folder name, so the command follows whatever the user has configured.
 */
export class GoToAttachmentFolderCommandHandler extends FileCommandHandler {
  private readonly app: App;
  private readonly attachmentPathManager: AttachmentPathManager;
  private readonly pluginNoticeComponent: PluginNoticeComponent;
  private readonly pluginSettingsComponent: PluginSettingsComponent;

  public constructor(params: GoToAttachmentFolderCommandHandlerConstructorParams) {
    super({
      fileMenuItemName: t(($) => $.menuItems.goToAttachmentFolder),
      icon: 'folder-open',
      id: 'go-to-attachment-folder',
      name: t(($) => $.commands.goToAttachmentFolder)
    });

    this.app = params.app;
    this.attachmentPathManager = params.attachmentPathManager;
    this.pluginNoticeComponent = params.pluginNoticeComponent;
    this.pluginSettingsComponent = params.pluginSettingsComponent;
  }

  protected override canExecuteFile(file: TFile): boolean {
    return this.pluginSettingsComponent.isNoteEx(file) && !this.pluginSettingsComponent.settings.isPathIgnored(file.path);
  }

  protected override async executeFile(file: TFile): Promise<void> {
    /*
     * `DUMMY_PATH` is what keeps `${prompt}` from opening a modal — navigating to a folder must never
     * ask the user to name an attachment that is not being saved.
     */
    const attachmentFolderPath = await this.attachmentPathManager.getAttachmentFolderFullPathForPath({
      actionContext: ActionContext.OpenFile,
      attachmentFileName: DUMMY_PATH,
      notePath: file.path
    });

    /*
     * A dummy that survived into the resolved path means the folder genuinely varies per attachment
     * (`${prompt}` or `${originalAttachmentFileName}` in the folder template), so this note has no one
     * folder to go to.
     */
    if (attachmentFolderPath.includes(DUMMY_PATH)) {
      this.pluginNoticeComponent.showNotice(t(($) => $.notice.attachmentFolderDependsOnAttachment, { notePath: file.path }));
      return;
    }

    const attachmentFolder = this.app.vault.getFolderByPath(attachmentFolderPath);
    if (attachmentFolder) {
      this.reveal(attachmentFolder);
      return;
    }

    this.showCreateFolderNotice(attachmentFolderPath);
  }

  protected override shouldAddToFileMenu(): boolean {
    return true;
  }

  private reveal(abstractFile: TAbstractFile): void {
    const fileExplorer = this.app.internalPlugins.getEnabledPluginById(InternalPluginName.FileExplorer);
    if (!fileExplorer) {
      this.pluginNoticeComponent.showNotice(t(($) => $.notice.fileExplorerDisabled, { path: abstractFile.path }));
      return;
    }

    fileExplorer.revealInFolder(abstractFile);
  }

  /**
   * Offers to create the folder rather than creating it silently. Going somewhere is a read; a command
   * the user reached for to navigate must not write to the vault on its own.
   */
  private showCreateFolderNotice(attachmentFolderPath: string): void {
    const button = new ButtonComponent(createDiv());
    button.setButtonText(t(($) => $.buttons.create));

    const notice = this.pluginNoticeComponent.showNotice(
      createFragment((f) => {
        f.appendText(t(($) => $.goToAttachmentFolder.doesNotExist.part1));
        f.appendText(' ');
        appendCodeBlock(f, attachmentFolderPath);
        f.appendText(' ');
        f.appendText(t(($) => $.goToAttachmentFolder.doesNotExist.part2));
        f.createEl('br');
        f.append(button.buttonEl);
      }),
      { shouldHideOnClick: false }
    );

    // Wired after the notice exists so the handler can dismiss it; the fragment is built before it.
    button.buttonEl.addEventListener('click', () => {
      notice.hide();
      invokeAsyncSafely(async () => {
        await createFolderSafe(this.app, attachmentFolderPath);
        const createdFolder = this.app.vault.getFolderByPath(attachmentFolderPath);
        if (createdFolder) {
          this.reveal(createdFolder);
        }
      });
    });
  }
}
