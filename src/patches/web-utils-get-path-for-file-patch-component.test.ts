import { castTo } from 'obsidian-dev-utils/object-utils';
import { strictProxy } from 'obsidian-dev-utils/strict-proxy';
import {
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import { WebUtilsGetPathForFilePatchComponent } from './web-utils-get-path-for-file-patch-component.ts';

interface FileWithPath {
  path: string;
}

describe('WebUtilsGetPathForFilePatchComponent', () => {
  let webUtils: Electron.WebUtils;
  let fallbackPath: string;

  beforeEach(() => {
    fallbackPath = '/fallback/path.png';
    webUtils = strictProxy<Electron.WebUtils>({
      getPathForFile: vi.fn().mockReturnValue(fallbackPath)
    });
  });

  function createComponent(): WebUtilsGetPathForFilePatchComponent {
    return new WebUtilsGetPathForFilePatchComponent({
      webUtils
    });
  }

  function createFile(path: string): File {
    return castTo<File>(strictProxy<FileWithPath>({ path }));
  }

  it('should register a single method patch on load', () => {
    const component = createComponent();
    const registerMethodPatchSpy = vi.spyOn(component, 'registerMethodPatch');

    component.load();

    expect(registerMethodPatchSpy).toHaveBeenCalledTimes(1);
  });

  it('should return the file path when it is present', () => {
    const component = createComponent();
    component.load();

    const result = webUtils.getPathForFile(createFile('/explicit/path.png'));

    expect(result).toBe('/explicit/path.png');
    expect(vi.mocked(webUtils.getPathForFile)).not.toHaveBeenCalled();
  });

  it('should fall back to the original method when the file path is missing', () => {
    const component = createComponent();
    component.load();

    const result = webUtils.getPathForFile(createFile(''));

    expect(result).toBe(fallbackPath);
    expect(vi.mocked(webUtils.getPathForFile)).toHaveBeenCalledTimes(1);
  });
});
