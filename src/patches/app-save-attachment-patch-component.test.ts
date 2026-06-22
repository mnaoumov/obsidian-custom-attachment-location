import type { App as AppOriginal } from 'obsidian';

import { strictProxy } from 'obsidian-dev-utils/strict-proxy';
import { App } from 'obsidian-test-mocks/obsidian';
import {
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { AttachmentSaver } from '../attachment-saver.ts';

import { AppSaveAttachmentPatchComponent } from './app-save-attachment-patch-component.ts';

interface AppWithSaveAttachment {
  saveAttachment(name: string, extension: string, data: ArrayBuffer): unknown;
}

describe('AppSaveAttachmentPatchComponent', () => {
  let app: AppOriginal;
  let attachmentSaver: AttachmentSaver;
  let savedFile: object;

  beforeEach(() => {
    app = App.createConfigured__().asOriginalType__();
    savedFile = {};
    attachmentSaver = strictProxy<AttachmentSaver>({
      saveAttachment: vi.fn().mockResolvedValue(savedFile)
    });
    Object.defineProperty(app, 'saveAttachment', {
      configurable: true,
      value: vi.fn(),
      writable: true
    });
  });

  function createComponent(): AppSaveAttachmentPatchComponent {
    return new AppSaveAttachmentPatchComponent({
      app,
      attachmentSaver
    });
  }

  it('should register a single method patch on load', () => {
    const component = createComponent();
    const registerMethodPatchSpy = vi.spyOn(component, 'registerMethodPatch');

    component.load();

    expect(registerMethodPatchSpy).toHaveBeenCalledTimes(1);
  });

  it('should delegate saveAttachment to the attachment saver with mapped arguments', async () => {
    const component = createComponent();
    component.load();

    const data = new ArrayBuffer(8);
    const appWithSaveAttachment = strictProxy<AppWithSaveAttachment>(app);
    const result = await appWithSaveAttachment.saveAttachment('base-name', 'png', data);

    expect(vi.mocked(attachmentSaver.saveAttachment)).toHaveBeenCalledWith({
      attachmentFileBaseName: 'base-name',
      attachmentFileContent: data,
      attachmentFileExtension: 'png'
    });
    expect(result).toBe(savedFile);
  });

  it('should restore the original method on unload', () => {
    const originalSaveAttachment = strictProxy<AppWithSaveAttachment>(app).saveAttachment;
    const component = createComponent();
    component.load();
    component.unload();

    expect(strictProxy<AppWithSaveAttachment>(app).saveAttachment).toBe(originalSaveAttachment);
  });
});
