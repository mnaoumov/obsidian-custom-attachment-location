import type { PluginNoticeComponent } from '@mnaoumov/obsidian-lib/components/plugin-notice-component';
import type { App } from 'obsidian';

import { GlobalCommandHandler } from '@mnaoumov/obsidian-lib/command-handlers/global-command-handler';
import { t } from '@mnaoumov/obsidian-lib/i18n/i18n';

import type { TokenValidator } from '../tokens/token-validator.ts';
import type { OriginalAttachmentNamesComponent } from './original-attachment-names-component.ts';

import { showOriginalAttachmentNamesModal } from './original-attachment-names-modal.ts';

interface ShowOriginalAttachmentNamesCommandHandlerConstructorParams {
  readonly app: App;
  readonly originalAttachmentNamesComponent: OriginalAttachmentNamesComponent;
  readonly pluginNoticeComponent: PluginNoticeComponent;
  readonly tokenValidator: TokenValidator;
}

/**
 * Lists every remembered original attachment name, where each can be edited, forgotten or reset.
 */
export class ShowOriginalAttachmentNamesCommandHandler extends GlobalCommandHandler {
  private readonly app: App;
  private readonly originalAttachmentNamesComponent: OriginalAttachmentNamesComponent;
  private readonly pluginNoticeComponent: PluginNoticeComponent;
  private readonly tokenValidator: TokenValidator;

  public constructor(params: ShowOriginalAttachmentNamesCommandHandlerConstructorParams) {
    super({
      icon: 'list',
      id: 'show-original-attachment-names',
      name: t(($) => $.commands.showOriginalAttachmentNames)
    });
    this.app = params.app;
    this.originalAttachmentNamesComponent = params.originalAttachmentNamesComponent;
    this.pluginNoticeComponent = params.pluginNoticeComponent;
    this.tokenValidator = params.tokenValidator;
  }

  protected override async execute(): Promise<void> {
    await showOriginalAttachmentNamesModal({
      app: this.app,
      originalAttachmentNamesComponent: this.originalAttachmentNamesComponent,
      pluginNoticeComponent: this.pluginNoticeComponent,
      tokenValidator: this.tokenValidator
    });
  }
}
