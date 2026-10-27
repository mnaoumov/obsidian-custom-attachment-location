import type {
  App as AppOriginal,
  FileManager as FileManagerOriginal,
  TFile
} from 'obsidian';

import { ensureNonNullable } from '@mnaoumov/typescript-lib/type-guards';
import { strictProxy } from '@mnaoumov/typescript-test-toolkit/strict-proxy';
import { App } from 'obsidian-test-mocks/obsidian';
import {
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { AttachmentPathManager } from '../attachment-location/attachment-path-manager.ts';
import type { PluginSettingsComponent } from '../settings/plugin-settings-component.ts';
import type { ImageSizeMap } from './image-size-map.ts';
import type { MarkdownUrlMap } from './markdown-url-map.ts';

import { PluginSettings } from '../settings/plugin-settings.ts';
import { FileManagerGenerateMarkdownLinkPatchComponent } from './file-manager-generate-markdown-link-patch-component.ts';

describe('FileManagerGenerateMarkdownLinkPatchComponent', () => {
  let app: AppOriginal;
  let fileManager: FileManagerOriginal;
  let settings: PluginSettings;
  let imageSizeMap: ImageSizeMap;
  let markdownUrlMap: MarkdownUrlMap;
  let attachmentPathManager: AttachmentPathManager;
  let pluginSettingsComponent: PluginSettingsComponent;
  let targetFile: TFile;
  let attachmentFile: TFile;
  let defaultLinkResult: string;
  let generateMarkdownLinkSpy: ReturnType<typeof vi.fn<(file: TFile, sourcePath: string, subpath?: string, alias?: string) => string>>;

  beforeEach(() => {
    const appMock = App.createConfigured__({
      files: {
        'folder/drawing.excalidraw.md': '',
        'folder/image.png': '',
        'folder/target.md': ''
      }
    });
    Object.defineProperty(appMock.vault, 'getConfig', {
      configurable: true,
      value: (name: string): unknown => name === 'useMarkdownLinks' || 'absolute',
      writable: true
    });
    app = appMock.asOriginalType__();
    targetFile = ensureNonNullable(app.vault.getFileByPath('folder/target.md'));
    attachmentFile = ensureNonNullable(app.vault.getFileByPath('folder/image.png'));

    settings = new PluginSettings();
    attachmentPathManager = strictProxy<AttachmentPathManager>({
      getInsertedLinkText: vi.fn().mockReturnValue('original report'),
      takeInsertedLinkText: vi.fn().mockReturnValue(undefined)
    });
    settings.markdownUrlFormat = '';

    imageSizeMap = strictProxy<ImageSizeMap>({
      getAndDelete: vi.fn().mockReturnValue(null)
    });
    markdownUrlMap = strictProxy<MarkdownUrlMap>({
      get: vi.fn().mockReturnValue(null)
    });
    pluginSettingsComponent = strictProxy<PluginSettingsComponent>({
      isNoteEx: (file: TFile): boolean => file.extension === 'md' && !file.path.endsWith('.excalidraw.md'),
      settings
    });

    defaultLinkResult = '[link](path.md)';
    generateMarkdownLinkSpy = vi.fn((_file: TFile, _sourcePath: string, _subpath?: string, _alias?: string): string => defaultLinkResult);
    fileManager = strictProxy<FileManagerOriginal>({
      generateMarkdownLink: (file: TFile, sourcePath: string, subpath?: string, alias?: string): string => generateMarkdownLinkSpy(file, sourcePath, subpath, alias)
    });
  });

  function createComponent(): FileManagerGenerateMarkdownLinkPatchComponent {
    return new FileManagerGenerateMarkdownLinkPatchComponent({
      app,
      attachmentPathManager,
      fileManager,
      imageSizeMap,
      markdownUrlMap,
      pluginSettingsComponent
    });
  }

  function invoke(subpath?: string, alias?: string): string {
    return fileManager.generateMarkdownLink(targetFile, 'note.md', subpath, alias);
  }

  it('uses the prepared original name for an inserted attachment link', () => {
    settings.insertedLinkText = '{{originalAttachmentFileName}}';
    const component = createComponent();
    component.load();
    const pdf = strictProxy<TFile>({ basename: 'renamed', extension: 'pdf', path: 'renamed.pdf' });

    fileManager.generateMarkdownLink(pdf, 'note.md');

    expect(generateMarkdownLinkSpy).toHaveBeenCalledWith(pdf, 'note.md', undefined, 'original report');
  });

  it.each([['photo', 'jpg'], ['300', 'png'], ['1920x1080', 'png'], ['a|b', 'png'], ['a]b', 'png'], ['a#b', 'png']])('leaves image %s.%s without a template alias to preserve embed sizing', (basename, extension) => {
    settings.insertedLinkText = '{{originalAttachmentFileName}}';
    const component = createComponent();
    component.load();
    const image = strictProxy<TFile>({ basename, extension, path: `${basename}.${extension}` });

    fileManager.generateMarkdownLink(image, 'note.md');

    expect(generateMarkdownLinkSpy).toHaveBeenCalledWith(image, 'note.md', undefined, undefined);
  });

  it('preserves an explicit alias over the inserted-link template', () => {
    settings.insertedLinkText = '{{originalAttachmentFileName}}';
    const component = createComponent();
    component.load();

    const pdf = strictProxy<TFile>({ basename: 'renamed', extension: 'pdf', path: 'renamed.pdf' });
    fileManager.generateMarkdownLink(pdf, 'note.md', undefined, 'chosen');

    expect(generateMarkdownLinkSpy).toHaveBeenCalledWith(pdf, 'note.md', undefined, 'chosen');
  });

  it('replaces unsafe link delimiters without changing the attachment target', () => {
    settings.insertedLinkText = '{{originalAttachmentFileName}}';
    vi.mocked(attachmentPathManager.getInsertedLinkText).mockReturnValue('a|b]c[d#e^f');
    const component = createComponent();
    component.load();
    const pdf = strictProxy<TFile>({ basename: 'renamed', extension: 'pdf', path: 'renamed.pdf' });

    fileManager.generateMarkdownLink(pdf, 'note.md', '#page=2');

    expect(generateMarkdownLinkSpy).toHaveBeenCalledWith(pdf, 'note.md', '#page=2', 'a｜b］c［d＃e＾f');
  });

  it('keeps the default when an asynchronous template has no prepared text', () => {
    settings.insertedLinkText = '{{noteFileName}}';
    vi.mocked(attachmentPathManager.getInsertedLinkText).mockReturnValue(undefined);
    const component = createComponent();
    component.load();
    const pdf = strictProxy<TFile>({ basename: 'renamed', extension: 'pdf', path: 'renamed.pdf' });
    fileManager.generateMarkdownLink(pdf, 'note.md');
    expect(generateMarkdownLinkSpy).toHaveBeenCalledWith(pdf, 'note.md', undefined, undefined);
  });

  it('turns template line breaks into spaces so the inserted link stays on one line', () => {
    settings.insertedLinkText = 'template';
    vi.mocked(attachmentPathManager.getInsertedLinkText).mockReturnValue('one\r\ntwo');
    const component = createComponent();
    component.load();
    const pdf = strictProxy<TFile>({ basename: 'renamed', extension: 'pdf', path: 'renamed.pdf' });
    fileManager.generateMarkdownLink(pdf, 'note.md');
    expect(generateMarkdownLinkSpy).toHaveBeenCalledWith(pdf, 'note.md', undefined, 'one  two');
  });

  it('should register a single method patch on load', () => {
    const component = createComponent();
    const registerMethodPatchSpy = vi.spyOn(component, 'registerMethodPatch');

    component.load();

    expect(registerMethodPatchSpy).toHaveBeenCalledTimes(1);
  });

  it('should apply the cached image size as alias when no alias is provided', () => {
    vi.mocked(imageSizeMap.getAndDelete).mockReturnValue('100x200');
    const component = createComponent();
    component.load();

    invoke();

    expect(vi.mocked(imageSizeMap.getAndDelete)).toHaveBeenCalledWith('folder/target.md');
  });

  it('should not look up an image size when an explicit alias is provided', () => {
    const component = createComponent();
    component.load();

    invoke(undefined, 'My Alias');

    expect(vi.mocked(imageSizeMap.getAndDelete)).not.toHaveBeenCalled();
  });

  it('should set the attachment base name as the alias when the setting is enabled (issue #24)', () => {
    settings.shouldSetLinkDisplayTextToAttachmentFileName = true;
    const component = createComponent();
    component.load();

    fileManager.generateMarkdownLink(attachmentFile, 'note.md');

    expect(generateMarkdownLinkSpy).toHaveBeenCalledWith(attachmentFile, 'note.md', undefined, 'image');
  });

  it('should not set a base-name alias for a note when the setting is enabled', () => {
    settings.shouldSetLinkDisplayTextToAttachmentFileName = true;
    const component = createComponent();
    component.load();

    invoke();

    expect(generateMarkdownLinkSpy).toHaveBeenCalledWith(targetFile, 'note.md', undefined, undefined);
  });

  it('should set the base-name alias for a drawing treated as an attachment when the setting is enabled', () => {
    settings.shouldSetLinkDisplayTextToAttachmentFileName = true;
    const drawingFile = ensureNonNullable(app.vault.getFileByPath('folder/drawing.excalidraw.md'));
    const component = createComponent();
    component.load();

    fileManager.generateMarkdownLink(drawingFile, 'note.md');

    expect(generateMarkdownLinkSpy).toHaveBeenCalledWith(drawingFile, 'note.md', undefined, 'drawing.excalidraw');
  });

  it('should not set a base-name alias when the setting is disabled', () => {
    settings.shouldSetLinkDisplayTextToAttachmentFileName = false;
    const component = createComponent();
    component.load();

    fileManager.generateMarkdownLink(attachmentFile, 'note.md');

    expect(generateMarkdownLinkSpy).toHaveBeenCalledWith(attachmentFile, 'note.md', undefined, undefined);
  });

  it('should prefer the cached image size over the base-name alias', () => {
    settings.shouldSetLinkDisplayTextToAttachmentFileName = true;
    vi.mocked(imageSizeMap.getAndDelete).mockReturnValue('100x200');
    const component = createComponent();
    component.load();

    fileManager.generateMarkdownLink(attachmentFile, 'note.md');

    expect(generateMarkdownLinkSpy).toHaveBeenCalledWith(attachmentFile, 'note.md', undefined, '100x200');
  });

  it('should return the default link when no markdown url format is configured', () => {
    const component = createComponent();
    component.load();

    const result = invoke();

    expect(result).toBe('[link](path.md)');
    expect(vi.mocked(markdownUrlMap.get)).not.toHaveBeenCalled();
  });

  it('should return the default link when there is no markdown url for the file', () => {
    settings.markdownUrlFormat = 'whatever';
    vi.mocked(markdownUrlMap.get).mockReturnValue(null);
    const component = createComponent();
    component.load();

    const result = invoke();

    expect(result).toBe('[link](path.md)');
    expect(vi.mocked(markdownUrlMap.get)).toHaveBeenCalledWith('folder/target.md');
  });

  it('should replace the url in a plain markdown link with the encoded markdown url', () => {
    settings.markdownUrlFormat = 'whatever';
    vi.mocked(markdownUrlMap.get).mockReturnValue('https://example.com/a b.png');
    const component = createComponent();
    component.load();

    const result = invoke();

    expect(result).toBe('[link](https://example.com/a%20b.png)');
  });

  it('should replace the url in an angle-bracket markdown link', () => {
    defaultLinkResult = '[link](<path with spaces.md>)';
    settings.markdownUrlFormat = 'whatever';
    vi.mocked(markdownUrlMap.get).mockReturnValue('https://example.com/image.png');
    const component = createComponent();
    component.load();

    const result = invoke();

    expect(result).toBe('[link](<https://example.com/image.png>)');
  });

  it('should convert a wikilink to a markdown link before replacing the url', () => {
    defaultLinkResult = '[[folder/target]]';
    settings.markdownUrlFormat = 'whatever';
    vi.mocked(markdownUrlMap.get).mockReturnValue('https://example.com/image.png');
    const component = createComponent();
    component.load();

    const result = invoke();

    expect(result).toContain('](https://example.com/image.png)');
    expect(result.startsWith('[')).toBe(true);
  });
});
