import { noopAsync } from '@mnaoumov/typescript-lib/function';
import { IDBFactory } from 'fake-indexeddb';
import {
  beforeEach,
  vi
} from 'vitest';

beforeEach(() => {
  vi.stubGlobal('indexedDB', new IDBFactory());
  const tails = new Map<string, Promise<unknown>>();
  const locks = {
    async request<T>(name: string, callback: () => Promise<T>): Promise<T> {
      const pending = (tails.get(name) ?? noopAsync()).catch(() => undefined).then(callback);
      tails.set(name, pending);
      return await pending;
    }
  };
  vi.stubGlobal(
    'navigator',
    new Proxy(navigator, {
      get(target, key): unknown {
        return key === 'locks' ? locks : Reflect.get(target, key, target);
      }
    })
  );
});
