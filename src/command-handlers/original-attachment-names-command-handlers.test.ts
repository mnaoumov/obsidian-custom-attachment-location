import type { ConsoleDebugComponent } from '@mnaoumov/obsidian-lib/components/console-debug-component';
import type { PluginNoticeComponent } from '@mnaoumov/obsidian-lib/components/plugin-notice-component';
import type {
  App as AppOriginal,
  TFile
} from 'obsidian';

import { initI18N } from '@mnaoumov/obsidian-lib/i18n/i18n';
import { castTo } from '@mnaoumov/typescript-lib/object-utils';
import { strictProxy } from '@mnaoumov/typescript-test-toolkit/strict-proxy';
import { App } from 'obsidian-test-mocks/obsidian';
import {
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { PluginSettingsComponent } from '../plugin-settings-component.ts';
import type { PluginSettings } from '../plugin-settings.ts';
import type { TokenValidator } from '../token-validator.ts';

import { translationsMap } from '../i18n/locales/translations-map.ts';
import { showOriginalAttachmentNamesModal } from '../modals/original-attachment-names-modal.ts';
import {
  PruneOriginalAttachmentNamesChoice,
  showPruneOriginalAttachmentNamesModal
} from '../modals/prune-original-attachment-names-modal.ts';
import { OriginalAttachmentNamesComponent } from '../original-attachment-names-component.ts';
import { PruneOriginalAttachmentNamesCommandHandler } from './prune-original-attachment-names-command-handler.ts';
import { RememberCurrentNameAsOriginalCommandHandler } from './remember-current-name-as-original-command-handler.ts';
import { ShowOriginalAttachmentNamesCommandHandler } from './show-original-attachment-names-command-handler.ts';

interface TestableExecute {
  execute: () => Promise<void>;
}

interface TestableFileHandler {
  canExecuteFile: (file: TFile) => boolean;
  executeFile: (file: TFile) => void;
  executeFiles: (files: TFile[]) => void;
  shouldAddToFileMenu: () => boolean;
  shouldAddToFilesMenu: () => boolean;
}

vi.mock('../modals/original-attachment-names-modal.ts', async (importOriginal) => ({
  ...await importOriginal<typeof import('../modals/original-attachment-names-modal.ts')>(),
  showOriginalAttachmentNamesModal: vi.fn()
}));

vi.mock('../modals/prune-original-attachment-names-modal.ts', async (importOriginal) => ({
  ...await importOriginal<typeof import('../modals/prune-original-attachment-names-modal.ts')>(),
  showPruneOriginalAttachmentNamesModal: vi.fn()
}));

const mockShowOriginalAttachmentNamesModal = vi.mocked(showOriginalAttachmentNamesModal);
const mockShowPruneOriginalAttachmentNamesModal = vi.mocked(showPruneOriginalAttachmentNamesModal);

let app: AppOriginal;
let originalAttachmentNamesComponent: OriginalAttachmentNamesComponent;
let showNotice: ReturnType<typeof vi.fn<PluginNoticeComponent['showNotice']>>;

beforeAll(async () => {
  await initI18N(translationsMap);
});

beforeEach(async () => {
  vi.clearAllMocks();
  app = App.createConfigured__().asOriginalType__();
  showNotice = vi.fn<PluginNoticeComponent['showNotice']>();
  originalAttachmentNamesComponent = new OriginalAttachmentNamesComponent({
    app,
    consoleDebugComponent: strictProxy<ConsoleDebugComponent>({ consoleDebug: vi.fn() }),
    pluginNoticeComponent: strictProxy<PluginNoticeComponent>({ showNotice }),
    pluginSettingsComponent: strictProxy<PluginSettingsComponent>({ settings: castTo<PluginSettings>({ shouldWarnWhenOriginalAttachmentNameIsUnknown: true }) }),
    storeFilePath: 'original-attachment-names.json'
  });
  originalAttachmentNamesComponent.load();
  await app.vault.createFolder('assets');
  await app.vault.createBinary('assets/live.png', new ArrayBuffer(1));
  originalAttachmentNamesComponent.set('assets/live.png', 'arrived.png');
  originalAttachmentNamesComponent.set('assets/gone.png', 'gone.png');
});

afterEach(() => {
  originalAttachmentNamesComponent.unload();
});

describe('ShowOriginalAttachmentNamesCommandHandler', () => {
  it('should open the list of original names', async () => {
    const tokenValidator = strictProxy<TokenValidator>({});
    const pluginNoticeComponent = strictProxy<PluginNoticeComponent>({ showNotice });
    const handler = new ShowOriginalAttachmentNamesCommandHandler({ app, originalAttachmentNamesComponent, pluginNoticeComponent, tokenValidator });

    await castTo<TestableExecute>(handler).execute();

    expect(mockShowOriginalAttachmentNamesModal).toHaveBeenCalledExactlyOnceWith({ app, originalAttachmentNamesComponent, pluginNoticeComponent, tokenValidator });
  });
});

describe('PruneOriginalAttachmentNamesCommandHandler', () => {
  function createHandler(): TestableExecute {
    return castTo<TestableExecute>(
      new PruneOriginalAttachmentNamesCommandHandler({
        app,
        originalAttachmentNamesComponent,
        pluginNoticeComponent: strictProxy<PluginNoticeComponent>({ showNotice })
      })
    );
  }

  it('should remove the stale records and keep the live ones when the user prunes', async () => {
    mockShowPruneOriginalAttachmentNamesModal.mockResolvedValue(PruneOriginalAttachmentNamesChoice.Prune);

    await createHandler().execute();

    expect(originalAttachmentNamesComponent.get('assets/gone.png')).toBeUndefined();
    expect(originalAttachmentNamesComponent.get('assets/live.png')).toBe('arrived.png');
    expect(showNotice).toHaveBeenCalledExactlyOnceWith('Removed 1 original attachment name(s) whose file no longer exists.');
  });

  it('should forget every record when the user forgets all', async () => {
    mockShowPruneOriginalAttachmentNamesModal.mockResolvedValue(PruneOriginalAttachmentNamesChoice.ForgetAll);

    await createHandler().execute();

    expect(originalAttachmentNamesComponent.size).toBe(0);
    expect(showNotice).toHaveBeenCalledExactlyOnceWith('Forgot 2 original attachment name(s).');
  });

  it('should refuse a choice the dialog cannot make', async () => {
    mockShowPruneOriginalAttachmentNamesModal.mockResolvedValue(castTo<PruneOriginalAttachmentNamesChoice>('Bogus'));

    await expect(createHandler().execute()).rejects.toThrow();
  });

  it('should change nothing when the user cancels', async () => {
    mockShowPruneOriginalAttachmentNamesModal.mockResolvedValue(PruneOriginalAttachmentNamesChoice.Cancel);

    await createHandler().execute();

    expect(originalAttachmentNamesComponent.size).toBe(2);
    expect(showNotice).not.toHaveBeenCalled();
  });
});

describe('RememberCurrentNameAsOriginalCommandHandler', () => {
  function createHandler(): TestableFileHandler {
    return castTo<TestableFileHandler>(
      new RememberCurrentNameAsOriginalCommandHandler({
        originalAttachmentNamesComponent,
        pluginNoticeComponent: strictProxy<PluginNoticeComponent>({ showNotice }),
        pluginSettingsComponent: strictProxy<PluginSettingsComponent>({
          isNoteEx: (pathOrFile: unknown) => castTo<TFile>(pathOrFile).extension === 'md'
        })
      })
    );
  }

  function createFile(path: string): TFile {
    return strictProxy<TFile>({
      extension: path.split('.').at(-1) ?? '',
      name: path.split('/').at(-1) ?? '',
      path
    });
  }

  it('should offer itself in the file menu and the multi-file menu, for attachments only', () => {
    const handler = createHandler();

    expect(handler.shouldAddToFileMenu()).toBe(true);
    expect(handler.shouldAddToFilesMenu()).toBe(true);
    expect(handler.canExecuteFile(createFile('assets/live.png'))).toBe(true);
    expect(handler.canExecuteFile(createFile('notes/note.md'))).toBe(false);
  });

  it('should remember the current name of one attachment as its original', () => {
    createHandler().executeFile(createFile('assets/live.png'));

    expect(originalAttachmentNamesComponent.get('assets/live.png')).toBe('live.png');
    expect(showNotice).toHaveBeenCalledExactlyOnceWith('Remembered the current name of 1 attachment(s) as the original.');
  });

  it('should remember the current names of a multi-selection with one notice', () => {
    createHandler().executeFiles([createFile('assets/live.png'), createFile('assets/other.jpg')]);

    expect(originalAttachmentNamesComponent.get('assets/live.png')).toBe('live.png');
    expect(originalAttachmentNamesComponent.get('assets/other.jpg')).toBe('other.jpg');
    expect(showNotice).toHaveBeenCalledExactlyOnceWith('Remembered the current name of 2 attachment(s) as the original.');
  });
});
