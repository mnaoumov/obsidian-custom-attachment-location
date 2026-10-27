// Cspell:words УХВАЛА
import {
  describe,
  expect,
  it
} from 'vitest';

import {
  findSidecarBase,
  getSidecarPath
} from './sidecar-matcher.ts';

describe('sidecar pairing', () => {
  it('keeps the full new base stem when the user removes its extension', () => {
    expect(getSidecarPath('folder/video', { baseName: 'video.mkv', shouldReplaceExtension: true, suffix: '.srt' })).toBe('folder/video.srt');
  });
  const extensions = ['p7s', '.SIG', 'asc', 'srt'];
  it('prefers the complete base name for detached signatures', () => {
    expect(findSidecarBase({ extensions, name: 'УХВАЛА.html.p7s', names: ['УХВАЛА.html', 'УХВАЛА.pdf'] })).toEqual({ baseName: 'УХВАЛА.html', suffix: '.p7s' });
  });
  it('pairs a subtitle with the only non-sidecar sharing its stem', () => {
    expect(findSidecarBase({ extensions, name: 'video.srt', names: ['video.mkv', 'video.asc'] })).toEqual({ baseName: 'video.mkv', shouldReplaceExtension: true, suffix: '.srt' });
  });
  it('preserves ambiguity instead of attaching a signature to an arbitrary document', () => {
    expect(findSidecarBase({ extensions, name: 'document.sig', names: ['document.pdf', 'document.html'] })).toBeNull();
  });
  it('leaves missing bases and ordinary attachments unpaired', () => {
    expect(findSidecarBase({ extensions, name: 'missing.p7s', names: [] })).toBeNull();
    expect(findSidecarBase({ extensions, name: 'video.pdf', names: ['video.mkv'] })).toBeUndefined();
    expect(findSidecarBase({ extensions: [], name: 'video.srt', names: ['video.mkv'] })).toBeUndefined();
  });
});
