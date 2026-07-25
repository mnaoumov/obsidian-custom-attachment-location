import {
  describe,
  expect,
  it
} from 'vitest';

import {
  getImageMimeType,
  isImageExtension
} from './image-mime-types.ts';

describe('image-mime-types', () => {
  describe('getImageMimeType', () => {
    it('should return the mime type for a known extension (case-insensitive)', () => {
      expect(getImageMimeType('png')).toBe('image/png');
      expect(getImageMimeType('PNG')).toBe('image/png');
      expect(getImageMimeType('JPG')).toBe('image/jpeg');
    });

    it('should return null for an unknown extension', () => {
      expect(getImageMimeType('txt')).toBeNull();
      expect(getImageMimeType('pdf')).toBeNull();
      expect(getImageMimeType('')).toBeNull();
    });
  });

  describe('isImageExtension', () => {
    it('should return true for a known image extension (case-insensitive)', () => {
      expect(isImageExtension('png')).toBe(true);
      expect(isImageExtension('WEBP')).toBe(true);
    });

    it('should return false for a non-image extension', () => {
      expect(isImageExtension('pdf')).toBe(false);
      expect(isImageExtension('md')).toBe(false);
    });
  });
});
