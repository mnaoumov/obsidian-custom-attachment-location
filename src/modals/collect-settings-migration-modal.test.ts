// @vitest-environment jsdom

import type { App as AppOriginal } from 'obsidian';

import {
  ButtonComponent,
  DropdownComponent,
  ExtraButtonComponent,
  TextAreaComponent,
  ToggleComponent
} from 'obsidian';
import { castTo } from 'obsidian-dev-utils/object-utils';
import { initI18N } from 'obsidian-dev-utils/obsidian/i18n/i18n';
import { App } from 'obsidian-test-mocks/obsidian';
import {
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type {
  MigratableSettingDescriptor,
  SettingsMigrationRow
} from '../collect-settings-migration.ts';

import {
  MIGRATABLE_SETTING_DESCRIPTORS,
  MigratableSettingKind
} from '../collect-settings-migration.ts';
import { translationsMap } from '../i18n/locales/translations-map.ts';
import { showCollectSettingsMigrationModal } from './collect-settings-migration-modal.ts';

/*
 * The modal's components keep their handlers on the component instance rather than on the DOM node, so a
 * `click()` on the rendered element would do nothing. The handlers are captured as they are registered,
 * which is what lets a test press OK, edit a value, or reset a row exactly the way a user does.
 */

const SOURCE_PLUGIN_NAME = 'Consistent Attachments and Links';

function getDescriptor(propertyName: MigratableSettingDescriptor['propertyName']): MigratableSettingDescriptor {
  const descriptor = MIGRATABLE_SETTING_DESCRIPTORS.find((candidate) => candidate.propertyName === propertyName);
  if (!descriptor) {
    throw new Error(`No descriptor for ${propertyName}`);
  }
  return descriptor;
}

const BOOLEAN_ROW: SettingsMigrationRow = {
  currentValue: false,
  descriptor: getDescriptor('shouldCollectAttachmentsAutomatically'),
  proposedValue: true
};

const COLLECT_MODE_ROW: SettingsMigrationRow = {
  currentValue: 'Skip',
  descriptor: getDescriptor('collectAttachmentUsedByMultipleNotesMode'),
  proposedValue: 'Move'
};

const MOVE_MODE_ROW: SettingsMigrationRow = {
  currentValue: 'CopyAll',
  descriptor: getDescriptor('moveAttachmentToProperFolderUsedByMultipleNotesMode'),
  proposedValue: 'Prompt'
};

const STRING_LIST_ROW: SettingsMigrationRow = {
  currentValue: [],
  descriptor: getDescriptor('attachmentUnitFolderPaths'),
  proposedValue: ['Pages']
};

let app: AppOriginal;
let buttonHandlers: Map<ButtonComponent, (mouseEvent: MouseEvent) => unknown>;
let dropdownHandlers: Map<DropdownComponent, (value: string) => void>;
let extraButtonHandlers: Map<ExtraButtonComponent, () => unknown>;
let textAreaHandlers: Map<TextAreaComponent, (value: string) => void>;
let toggleHandlers: Map<ToggleComponent, (isEnabled: boolean) => void>;

beforeAll(async () => {
  await initI18N(translationsMap);
});

beforeEach(() => {
  app = App.createConfigured__().asOriginalType__();
  buttonHandlers = new Map<ButtonComponent, (mouseEvent: MouseEvent) => unknown>();
  dropdownHandlers = new Map<DropdownComponent, (value: string) => void>();
  extraButtonHandlers = new Map<ExtraButtonComponent, () => unknown>();
  textAreaHandlers = new Map<TextAreaComponent, (value: string) => void>();
  toggleHandlers = new Map<ToggleComponent, (isEnabled: boolean) => void>();

  vi.spyOn(ButtonComponent.prototype, 'onClick').mockImplementation(function onClickMock(this: ButtonComponent, callback: (mouseEvent: MouseEvent) => unknown): ButtonComponent {
    buttonHandlers.set(this, callback);
    return this;
  });

  vi.spyOn(ExtraButtonComponent.prototype, 'onClick').mockImplementation(
    function onClickMock(this: ExtraButtonComponent, callback: () => unknown): ExtraButtonComponent {
      extraButtonHandlers.set(this, callback);
      return this;
    }
  );

  vi.spyOn(ToggleComponent.prototype, 'onChange').mockImplementation(
    function onChangeMock(this: ToggleComponent, callback: (isEnabled: boolean) => void): ToggleComponent {
      toggleHandlers.set(this, callback);
      return this;
    }
  );

  vi.spyOn(DropdownComponent.prototype, 'onChange').mockImplementation(
    function onChangeMock(this: DropdownComponent, callback: (value: string) => void): DropdownComponent {
      dropdownHandlers.set(this, callback);
      return this;
    }
  );

  vi.spyOn(TextAreaComponent.prototype, 'onChange').mockImplementation(
    function onChangeMock(this: TextAreaComponent, callback: (value: string) => void): TextAreaComponent {
      textAreaHandlers.set(this, callback);
      return this;
    }
  );
});

function pressButton(buttonText: string): void {
  for (const [buttonComponent, handler] of buttonHandlers) {
    if (buttonComponent.buttonEl.textContent === buttonText) {
      handler(castTo<MouseEvent>({}));
      return;
    }
  }

  throw new Error(`The dialog has no "${buttonText}" button`);
}

describe('showCollectSettingsMigrationModal', () => {
  it('should apply the proposal as it stands when the user presses OK', async () => {
    const rowsPromise = showCollectSettingsMigrationModal({
      app,
      rows: [BOOLEAN_ROW],
      sourcePluginName: SOURCE_PLUGIN_NAME
    });

    pressButton('OK');

    expect(await rowsPromise).toEqual([BOOLEAN_ROW]);
  });

  it('should write nothing when the user cancels', async () => {
    const rowsPromise = showCollectSettingsMigrationModal({
      app,
      rows: [BOOLEAN_ROW],
      sourcePluginName: SOURCE_PLUGIN_NAME
    });

    pressButton('Cancel');

    expect(await rowsPromise).toBeNull();
  });

  it('should carry every edited value into the approved rows', async () => {
    const rowsPromise = showCollectSettingsMigrationModal({
      app,
      rows: [
        BOOLEAN_ROW,
        COLLECT_MODE_ROW,
        MOVE_MODE_ROW,
        STRING_LIST_ROW
      ],
      sourcePluginName: SOURCE_PLUGIN_NAME
    });

    for (const handler of toggleHandlers.values()) {
      handler(false);
    }

    const [collectModeHandler, moveModeHandler] = [...dropdownHandlers.values()];
    collectModeHandler?.('Copy');
    // A value the dropdown could not have produced is ignored rather than stored.
    collectModeHandler?.('CopyAll');
    moveModeHandler?.('Skip');
    moveModeHandler?.('Move');

    for (const handler of textAreaHandlers.values()) {
      handler('Pages\n\n  Drawings  \n');
    }

    pressButton('OK');

    const rows = await rowsPromise;
    expect(rows?.map((row) => row.proposedValue)).toEqual([false, 'Copy', 'Skip', ['Pages', 'Drawings']]);
  });

  it('should reset a row to the current value, which is how one setting is declined', async () => {
    const rowsPromise = showCollectSettingsMigrationModal({
      app,
      rows: [
        BOOLEAN_ROW,
        COLLECT_MODE_ROW,
        MOVE_MODE_ROW,
        STRING_LIST_ROW
      ],
      sourcePluginName: SOURCE_PLUGIN_NAME
    });

    for (const handler of extraButtonHandlers.values()) {
      handler();
    }

    pressButton('OK');

    const rows = await rowsPromise;
    expect(rows?.map((row) => row.proposedValue)).toEqual([
      BOOLEAN_ROW.currentValue,
      COLLECT_MODE_ROW.currentValue,
      MOVE_MODE_ROW.currentValue,
      STRING_LIST_ROW.currentValue
    ]);
  });

  it('should refuse a row whose kind it cannot render', async () => {
    await expect(async () => {
      await showCollectSettingsMigrationModal({
        app,
        rows: [{
          ...BOOLEAN_ROW,
          descriptor: {
            ...BOOLEAN_ROW.descriptor,
            kind: castTo<MigratableSettingKind>('Unknown')
          }
        }],
        sourcePluginName: SOURCE_PLUGIN_NAME
      });
    }).rejects.toThrow();
  });
});
