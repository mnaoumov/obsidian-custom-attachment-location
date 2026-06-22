import type {
  App as AppOriginal,
  FileManager as FileManagerOriginal,
  TFile
} from 'obsidian';

import { strictProxy } from 'obsidian-dev-utils/strict-proxy';
import { ensureNonNullable } from 'obsidian-dev-utils/type-guards';
import { App } from 'obsidian-test-mocks/obsidian';
import {
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { ImageSizeMap } from '../image-size-map.ts';
import type { MarkdownUrlMap } from '../markdown-url-map.ts';
import type { PluginSettingsComponent } from '../plugin-settings-component.ts';

import { PluginSettings } from '../plugin-settings.ts';
import { FileManagerGenerateMarkdownLinkPatchComponent } from './file-manager-generate-markdown-link-patch-component.ts';

describe('FileManagerGenerateMarkdownLinkPatchComponent', () => {
  let app: AppOriginal;
  let fileManager: FileManagerOriginal;
  let settings: PluginSettings;
  let imageSizeMap: ImageSizeMap;
  let markdownUrlMap: MarkdownUrlMap;
  let pluginSettingsComponent: PluginSettingsComponent;
  let targetFile: TFile;
  let defaultLinkResult: string;
  let generateMarkdownLinkSpy: ReturnType<typeof vi.fn<() => string>>;

  beforeEach(() => {
    const appMock = App.createConfigured__({
      files: {
        'folder/target.md': ''
      }
    });
    Object.defineProperty(appMock.vault, 'getConfig', {
      configurable: true,
      value: (name: string): unknown => name === 'useMarkdownLinks' ? true : 'absolute',
      writable: true
    });
    app = appMock.asOriginalType__();
    targetFile = ensureNonNullable(app.vault.getFileByPath('folder/target.md'));

    settings = new PluginSettings();
    settings.markdownUrlFormat = '';

    imageSizeMap = strictProxy<ImageSizeMap>({
      getAndDelete: vi.fn().mockReturnValue(null)
    });
    markdownUrlMap = strictProxy<MarkdownUrlMap>({
      get: vi.fn().mockReturnValue(null)
    });
    pluginSettingsComponent = strictProxy<PluginSettingsComponent>({
      settings
    });

    defaultLinkResult = '[link](path.md)';
    generateMarkdownLinkSpy = vi.fn((): string => defaultLinkResult);
    fileManager = strictProxy<FileManagerOriginal>({
      generateMarkdownLink: (_file: TFile, _sourcePath: string, _subpath?: string, _alias?: string): string => generateMarkdownLinkSpy()
    });
  });

  function createComponent(): FileManagerGenerateMarkdownLinkPatchComponent {
    return new FileManagerGenerateMarkdownLinkPatchComponent({
      app,
      fileManager,
      imageSizeMap,
      markdownUrlMap,
      pluginSettingsComponent
    });
  }

  function invoke(subpath?: string, alias?: string): string {
    return fileManager.generateMarkdownLink(targetFile, 'note.md', subpath, alias);
  }

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
