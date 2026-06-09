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
import {
  DEFAULT_LANGUAGE,
  translationsMap
} from './translations-map.ts';
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

  it('should default to the en language', () => {
    expect(DEFAULT_LANGUAGE).toBe('en');
  });

  it('should expose a translations object for every supported locale', () => {
    for (const value of Object.values(translationsMap)) {
      expect(value).toBeTypeOf('object');
    }
  });
});
