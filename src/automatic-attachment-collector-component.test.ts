// @vitest-environment jsdom

import type {
  App,
  EventRef,
  TFile
} from 'obsidian';

import { castTo } from 'obsidian-dev-utils/object-utils';
import { strictProxy } from 'obsidian-dev-utils/strict-proxy';
import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { AttachmentCollector } from './attachment-collector.ts';
import type { PluginSettingsComponent } from './plugin-settings-component.ts';

import { AutomaticAttachmentCollectorComponent } from './automatic-attachment-collector-component.ts';
import { PluginSettings } from './plugin-settings.ts';

interface LayoutReadyTrigger {
  onLayoutReady: () => void;
}

describe('AutomaticAttachmentCollectorComponent', () => {
  const NOTE = strictProxy<TFile>({ path: 'note.md' });

  let collectAttachmentsAutomatically: ReturnType<typeof vi.fn<AttachmentCollector['collectAttachmentsAutomatically']>>;
  let changedHandler: ((file: TFile) => void) | null;
  let isNoteEx: ReturnType<typeof vi.fn<PluginSettingsComponent['isNoteEx']>>;
  let settings: PluginSettings;

  function startListening(): void {
    const component = new AutomaticAttachmentCollectorComponent({
      app: strictProxy<App>({
        metadataCache: strictProxy<App['metadataCache']>({
          on: castTo<App['metadataCache']['on']>((name: string, callback: (file: TFile) => void): EventRef => {
            expect(name).toBe('changed');
            changedHandler = callback;
            return castTo<EventRef>({});
          })
        })
      }),
      attachmentCollector: strictProxy<AttachmentCollector>({ collectAttachmentsAutomatically }),
      pluginSettingsComponent: strictProxy<PluginSettingsComponent>({
        isNoteEx,
        settings
      })
    });
    castTo<LayoutReadyTrigger>(component).onLayoutReady();
  }

  function changeNote(): void {
    if (!changedHandler) {
      throw new Error('The component is not listening for changes');
    }
    changedHandler(NOTE);
  }

  beforeEach(() => {
    changedHandler = null;
    collectAttachmentsAutomatically = vi.fn<AttachmentCollector['collectAttachmentsAutomatically']>();
    isNoteEx = vi.fn<PluginSettingsComponent['isNoteEx']>().mockReturnValue(true);
    settings = new PluginSettings();
    settings.shouldCollectAttachmentsAutomatically = true;
  });

  afterEach(() => {
    document.body.empty();
  });

  /*
   * The jsdom environment lays nothing out, so `isShown()` cannot tell a visible element from a hidden one
   * there. The suggester's visibility is stated instead, which is the one fact the component reads off it.
   */
  function addSuggestionContainer(isShown: boolean): void {
    const suggestionContainer = document.body.createDiv({ cls: 'suggestion-container' });
    suggestionContainer.isShown = (): boolean => isShown;
  }

  it('should collect a note that changed while the setting is on', () => {
    startListening();
    changeNote();

    expect(collectAttachmentsAutomatically).toHaveBeenCalledWith(NOTE);
  });

  it('should do nothing while the setting is off, which is the default', () => {
    settings.shouldCollectAttachmentsAutomatically = new PluginSettings().shouldCollectAttachmentsAutomatically;
    startListening();
    changeNote();

    expect(collectAttachmentsAutomatically).not.toHaveBeenCalled();
  });

  it('should read the setting at each change, so turning it on needs no reload', () => {
    settings.shouldCollectAttachmentsAutomatically = false;
    startListening();
    settings.shouldCollectAttachmentsAutomatically = true;
    changeNote();

    expect(collectAttachmentsAutomatically).toHaveBeenCalledWith(NOTE);
  });

  it('should leave a file that is not a note alone', () => {
    isNoteEx.mockReturnValue(false);
    startListening();
    changeNote();

    expect(collectAttachmentsAutomatically).not.toHaveBeenCalled();
  });

  it('should wait while the link suggester is open, since the link being typed is not finished', () => {
    addSuggestionContainer(true);
    startListening();
    changeNote();

    expect(collectAttachmentsAutomatically).not.toHaveBeenCalled();
  });

  it('should collect once the link suggester is closed again', () => {
    addSuggestionContainer(false);
    startListening();
    changeNote();

    expect(collectAttachmentsAutomatically).toHaveBeenCalledWith(NOTE);
  });
});
