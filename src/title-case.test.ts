import {
  describe,
  expect,
  it
} from 'vitest';

import {
  collapseWhitespace,
  toTitleCase
} from './title-case.ts';

describe('collapseWhitespace', () => {
  it('should collapse every whitespace run to a single space', () => {
    expect(collapseWhitespace('alpha   bravo')).toBe('alpha bravo');
  });

  it('should remove leading and trailing whitespace', () => {
    expect(collapseWhitespace('   alpha bravo   ')).toBe('alpha bravo');
  });

  it('should treat tabs and newlines as whitespace', () => {
    expect(collapseWhitespace('alpha\t\nbravo')).toBe('alpha bravo');
  });

  it('should leave an already clean value alone', () => {
    expect(collapseWhitespace('alpha bravo')).toBe('alpha bravo');
  });

  it('should return an empty string for whitespace only', () => {
    expect(collapseWhitespace(' '.repeat(3))).toBe('');
  });
});

describe('toTitleCase', () => {
  it('should capitalize the first letter of each word and lower-case the rest', () => {
    expect(toTitleCase('alpha bRAVo charlie')).toBe('Alpha Bravo Charlie');
  });

  it('should leave a fully upper-case word alone so an acronym survives', () => {
    expect(toTitleCase('api TEST report')).toBe('Api TEST Report');
  });

  it('should still capitalize a single upper-case letter, which is not an acronym', () => {
    // Below the acronym length the rule is indistinguishable from ordinary title-casing.
    expect(toTitleCase('a bravo')).toBe('A Bravo');
  });

  it('should treat a hyphen as a word separator and keep it', () => {
    expect(toTitleCase('alpha-bravo')).toBe('Alpha-Bravo');
  });

  it('should keep a spaced hyphen distinguishable from a joined one', () => {
    expect(toTitleCase('alpha - bravo')).toBe('Alpha - Bravo');
  });

  it('should preserve the exact whitespace it was given', () => {
    // Collapsing is `collapseWhitespace`'s job; doing it here as well would make the two impossible
    // To compose in either order.
    expect(toTitleCase('alpha   bravo')).toBe('Alpha   Bravo');
  });

  it('should return an empty string unchanged', () => {
    expect(toTitleCase('')).toBe('');
  });
});
