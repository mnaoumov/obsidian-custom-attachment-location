/**
 * @file
 *
 * `Collect attachments automatically`: collects a note's attachments each time the note changes.
 *
 * Driven by `metadataCache` `changed` rather than by `vault` `modify`, because a collect reads the note's
 * links from the metadata cache, and `changed` is the event that says the cache has caught up with the edit.
 * The collect this starts rewrites the note's links, which fires `changed` again. That second run finds
 * every attachment in place and moves nothing, so the pair converges. See
 * `AttachmentPathManager.isParkedBesideProperPath` for the one case that used not to.
 */

import type {
  App,
  TFile
} from 'obsidian';

import { LayoutReadyComponent } from 'obsidian-dev-utils/obsidian/components/layout-ready-component';

import type { AttachmentCollector } from './attachment-collector.ts';
import type { PluginSettingsComponent } from './plugin-settings-component.ts';

interface AutomaticAttachmentCollectorComponentConstructorParams {
  readonly app: App;
  readonly attachmentCollector: AttachmentCollector;
  readonly pluginSettingsComponent: PluginSettingsComponent;
}

/**
 * Collects a note's attachments whenever the note changes, while the setting is on.
 */
export class AutomaticAttachmentCollectorComponent extends LayoutReadyComponent {
  private readonly attachmentCollector: AttachmentCollector;
  private readonly pluginSettingsComponent: PluginSettingsComponent;

  public constructor(params: AutomaticAttachmentCollectorComponentConstructorParams) {
    super(params.app);
    this.attachmentCollector = params.attachmentCollector;
    this.pluginSettingsComponent = params.pluginSettingsComponent;
  }

  /**
   * Starts listening once the layout is ready, so the vault's initial indexing does not collect every note.
   */
  protected override onLayoutReady(): void {
    this.registerEvent(this.app.metadataCache.on('changed', this.handleMetadataCacheChanged.bind(this)));
  }

  private handleMetadataCacheChanged(file: TFile): void {
    if (!this.pluginSettingsComponent.settings.shouldCollectAttachmentsAutomatically) {
      return;
    }

    if (!this.pluginSettingsComponent.isNoteEx(file)) {
      return;
    }

    /*
     * The link suggester is open, so the user is in the middle of typing a link. The cache already holds the
     * half-typed link, and collecting now would act on a link that is not finished yet.
     */
    const suggestionContainer = activeDocument.querySelector<HTMLDivElement>('.suggestion-container');
    if (suggestionContainer?.isShown()) {
      return;
    }

    this.attachmentCollector.collectAttachmentsAutomatically(file);
  }
}
