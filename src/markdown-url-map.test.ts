import {
  describe,
  expect,
  it
} from 'vitest';

import { MarkdownUrlMap } from './markdown-url-map.ts';

describe('MarkdownUrlMap', () => {
  describe('get', () => {
    it('should return null when the path is not present', () => {
      const map = new MarkdownUrlMap();
      expect(map.get('missing.md')).toBeNull();
    });

    it('should return the stored url when present', () => {
      const map = new MarkdownUrlMap();
      map.set('note.md', 'https://example.com');
      expect(map.get('note.md')).toBe('https://example.com');
    });
  });

  describe('set', () => {
    it('should overwrite an existing url for the same path', () => {
      const map = new MarkdownUrlMap();
      map.set('note.md', 'https://example.com/a');
      map.set('note.md', 'https://example.com/b');
      expect(map.get('note.md')).toBe('https://example.com/b');
    });
  });

  describe('delete', () => {
    it('should remove the stored url for the path', () => {
      const map = new MarkdownUrlMap();
      map.set('note.md', 'https://example.com');
      map.delete('note.md');
      expect(map.get('note.md')).toBeNull();
    });

    it('should be a no-op when the path is not present', () => {
      const map = new MarkdownUrlMap();
      map.delete('missing.md');
      expect(map.get('missing.md')).toBeNull();
    });
  });
});
