import {
  describe,
  expect,
  it
} from 'vitest';

import { ImageSizeMap } from './image-size-map.ts';

describe('ImageSizeMap', () => {
  describe('getAndDelete', () => {
    it('should return null when the path is not present', () => {
      const map = new ImageSizeMap();
      expect(map.getAndDelete('missing.png')).toBeNull();
    });

    it('should return the size and delete the entry when present', () => {
      const map = new ImageSizeMap();
      map.set('image.png', '100x200');
      expect(map.getAndDelete('image.png')).toBe('100x200');
      expect(map.getAndDelete('image.png')).toBeNull();
    });

    it('should not delete the entry when the stored size is falsy', () => {
      const map = new ImageSizeMap();
      map.set('image.png', '');
      expect(map.getAndDelete('image.png')).toBe('');
      expect(map.getAndDelete('image.png')).toBe('');
    });
  });

  describe('set', () => {
    it('should overwrite an existing size for the same path', () => {
      const map = new ImageSizeMap();
      map.set('image.png', '10x10');
      map.set('image.png', '20x20');
      expect(map.getAndDelete('image.png')).toBe('20x20');
    });
  });
});
