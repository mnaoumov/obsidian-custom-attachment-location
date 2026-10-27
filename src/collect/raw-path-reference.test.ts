import {
  describe,
  expect,
  it
} from 'vitest';

import { isReferencedByRawPath } from './raw-path-reference.ts';

describe('isReferencedByRawPath', () => {
  it('should match the full vault-relative path as a substring', () => {
    expect(isReferencedByRawPath({
      attachmentPath: 'folder/img.png',
      content: '<img src="folder/img.png">'
    })).toBe(true);
  });

  it('should match the bare file name at a boundary', () => {
    expect(isReferencedByRawPath({
      attachmentPath: 'folder/img.png',
      content: 'see ![](img.png) rendered'
    })).toBe(true);
  });

  it('should not match a longer file name that merely ends with the needle', () => {
    expect(isReferencedByRawPath({
      attachmentPath: 'img.png',
      content: 'this is myimg.png only'
    })).toBe(false);
  });

  it('should not match a same-named file in a different folder', () => {
    expect(isReferencedByRawPath({
      attachmentPath: 'img.png',
      content: 'unrelated folder/img.png reference'
    })).toBe(false);
  });

  it('should match a URL-encoded file name', () => {
    expect(isReferencedByRawPath({
      attachmentPath: 'my img.png',
      content: 'slider: my%20img.png'
    })).toBe(true);
  });

  it('should return false when nothing references the attachment', () => {
    expect(isReferencedByRawPath({
      attachmentPath: 'folder/img.png',
      content: 'no references here at all'
    })).toBe(false);
  });

  it('should return false for an empty attachment path', () => {
    expect(isReferencedByRawPath({
      attachmentPath: '',
      content: 'anything'
    })).toBe(false);
  });
});
