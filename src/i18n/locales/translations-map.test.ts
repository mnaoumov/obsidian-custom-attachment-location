import {
  describe,
  expect,
  it
} from 'vitest';

import { am } from './am.ts';
import { ar } from './ar.ts';
import { be } from './be.ts';
import { ca } from './ca.ts';
import { cs } from './cs.ts';
import { da } from './da.ts';
import { de } from './de.ts';
import { enGB } from './en-gb.ts';
import { en } from './en.ts';
import { es } from './es.ts';
import { fa } from './fa.ts';
import { fr } from './fr.ts';
import { ga } from './ga.ts';
import { he } from './he.ts';
import { hu } from './hu.ts';
import { id } from './id.ts';
import { it as itLocale } from './it.ts';
import { ja } from './ja.ts';
import { kh } from './kh.ts';
import { ko } from './ko.ts';
import { lv } from './lv.ts';
import { ms } from './ms.ts';
import { ne } from './ne.ts';
import { nl } from './nl.ts';
import { no } from './no.ts';
import { pl } from './pl.ts';
import { ptBR } from './pt-br.ts';
import { pt } from './pt.ts';
import { ro } from './ro.ts';
import { ru } from './ru.ts';
import { sq } from './sq.ts';
import { th } from './th.ts';
import { tr } from './tr.ts';
import { translationsMap } from './translations-map.ts';
import { uk } from './uk.ts';
import { uz } from './uz.ts';
import { vi } from './vi.ts';
import { zhTW } from './zh-tw.ts';
import { zh } from './zh.ts';

describe('translationsMap', () => {
  it('should map every locale key to its translations object', () => {
    expect(translationsMap).toStrictEqual({
      am,
      ar,
      be,
      ca,
      cs,
      da,
      de,
      en,
      'en-GB': enGB,
      es,
      fa,
      fr,
      ga,
      he,
      hu,
      id,
      'it': itLocale,
      ja,
      kh,
      ko,
      lv,
      ms,
      ne,
      nl,
      no,
      pl,
      pt,
      'pt-BR': ptBR,
      ro,
      ru,
      sq,
      th,
      tr,
      uk,
      uz,
      vi,
      zh,
      'zh-TW': zhTW
    });
  });

  it('should reference the same en object instance', () => {
    expect(translationsMap.en).toBe(en);
  });

  it('should keep URLs out of every locale string, so each URL is defined once in code', () => {
    const offenders: string[] = [];

    function collect(value: unknown, path: string): void {
      if (typeof value === 'string') {
        if (/https?:\/\//i.test(value)) {
          offenders.push(path);
        }
        return;
      }

      if (typeof value === 'object' && value !== null) {
        for (const [key, child] of Object.entries(value)) {
          collect(child, `${path}.${key}`);
        }
      }
    }

    for (const [locale, translations] of Object.entries(translationsMap)) {
      collect(translations, locale);
    }

    expect(offenders).toStrictEqual([]);
  });

  it('should keep every sentence whole, with no part<N> fragment keys in any locale', () => {
    const offenders: string[] = [];

    function collect(value: unknown, path: string): void {
      if (typeof value !== 'object' || value === null) {
        return;
      }

      for (const [key, child] of Object.entries(value)) {
        if (/^part\d+$/.test(key)) {
          offenders.push(`${path}.${key}`);
        }
        collect(child, `${path}.${key}`);
      }
    }

    for (const [locale, translations] of Object.entries(translationsMap)) {
      collect(translations, locale);
    }

    expect(offenders).toStrictEqual([]);
  });

  it('should only translate keys the default translations define, with the same shape', () => {
    const offenders: string[] = [];

    function collect(value: unknown, defaultValue: unknown, path: string): void {
      if (typeof value === 'string') {
        if (typeof defaultValue !== 'string') {
          offenders.push(path);
        }
        return;
      }

      if (typeof value !== 'object' || value === null || typeof defaultValue !== 'object' || defaultValue === null) {
        offenders.push(path);
        return;
      }

      for (const [key, child] of Object.entries(value)) {
        collect(child, (defaultValue as Record<string, unknown>)[key], `${path}.${key}`);
      }
    }

    for (const [locale, translations] of Object.entries(translationsMap)) {
      collect(translations, en, locale);
    }

    expect(offenders).toStrictEqual([]);
  });

  it('should keep the placeholders of every translated string the same as the default one', () => {
    const offenders: string[] = [];

    // The distinct placeholder names, sorted: a translation may repeat or reorder them, but not drop or rename one.
    function placeholders(text: string): string {
      const names = [...text.matchAll(/\{\{(?<name>[^}]+)\}\}/g)].map((match) => match.groups?.['name'] ?? '');
      return [...new Set(names)].sort().join(',');
    }

    function collect(value: unknown, defaultValue: unknown, path: string): void {
      if (typeof value === 'string' && typeof defaultValue === 'string') {
        if (placeholders(value) !== placeholders(defaultValue)) {
          offenders.push(path);
        }
        return;
      }

      if (typeof value === 'object' && value !== null && typeof defaultValue === 'object' && defaultValue !== null) {
        for (const [key, child] of Object.entries(value)) {
          collect(child, (defaultValue as Record<string, unknown>)[key], `${path}.${key}`);
        }
      }
    }

    for (const [locale, translations] of Object.entries(translationsMap)) {
      collect(translations, en, locale);
    }

    expect(offenders).toStrictEqual([]);
  });

  it('should expose a translations object for every supported locale', () => {
    for (const value of Object.values(translationsMap)) {
      expect(value).toBeTypeOf('object');
    }
  });
});
