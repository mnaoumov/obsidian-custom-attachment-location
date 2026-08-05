import type {
  App,
  Notice
} from 'obsidian';
import type { LinkUpdateProgressReporter } from 'obsidian-dev-utils/obsidian/link-update-progress';
import type { Mock } from 'vitest';

import { castTo } from 'obsidian-dev-utils/object-utils';
import { PluginNoticeComponent } from 'obsidian-dev-utils/obsidian/components/plugin-notice-component';
import { initI18N } from 'obsidian-dev-utils/obsidian/i18n/i18n';
import { strictProxy } from 'obsidian-dev-utils/strict-proxy';
import {
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import { translationsMap } from './i18n/locales/translations-map.ts';
import { createLinkUpdateProgressReporter } from './link-update-progress-reporter.ts';

const PLUGIN_NAME = 'Custom Attachment Location';

interface NoticeLike {
  hide: Mock;
  setMessage: Mock;
}

describe('createLinkUpdateProgressReporter', () => {
  let notices: NoticeLike[];
  let reporter: LinkUpdateProgressReporter;
  let showNoticeSpy: Mock;

  beforeAll(async () => {
    await initI18N(translationsMap);
  });

  beforeEach(() => {
    vi.clearAllMocks();
    notices = [];
    const app = strictProxy<App>({});
    const pluginNoticeComponent = new PluginNoticeComponent({ app, pluginName: PLUGIN_NAME });
    showNoticeSpy = vi.fn(() => {
      const notice: NoticeLike = {
        hide: vi.fn(),
        setMessage: vi.fn()
      };
      notices.push(notice);
      return castTo<Notice>(notice);
    });
    vi.spyOn(pluginNoticeComponent, 'showNotice').mockImplementation((...$arguments) => castTo<PluginNoticeComponent['showNotice']>(showNoticeSpy)(...$arguments));
    reporter = createLinkUpdateProgressReporter({ pluginNoticeComponent });
  });

  it('should show a single permanent notice on the first progress update', () => {
    reporter({ currentPath: 'a.md', processed: 1, total: 3 });
    expect(showNoticeSpy).toHaveBeenCalledExactlyOnceWith('Updating links: 1/3 - \'a.md\'', { isPermanent: true });
    expect(notices).toHaveLength(1);
    expect(notices[0]?.setMessage).not.toHaveBeenCalled();
    expect(notices[0]?.hide).not.toHaveBeenCalled();
  });

  it('should update the existing notice in place on subsequent progress updates', () => {
    reporter({ currentPath: 'a.md', processed: 1, total: 3 });
    reporter({ currentPath: 'b.md', processed: 2, total: 3 });
    expect(showNoticeSpy).toHaveBeenCalledOnce();
    expect(notices).toHaveLength(1);
    expect(notices[0]?.setMessage).toHaveBeenCalledExactlyOnceWith('Updating links: 2/3 - \'b.md\'');
    expect(notices[0]?.hide).not.toHaveBeenCalled();
  });

  it('should dismiss the notice once every file has been processed', () => {
    reporter({ currentPath: 'a.md', processed: 1, total: 3 });
    reporter({ currentPath: 'b.md', processed: 2, total: 3 });
    reporter({ currentPath: 'c.md', processed: 3, total: 3 });
    expect(notices).toHaveLength(1);
    expect(notices[0]?.setMessage).toHaveBeenLastCalledWith('Updating links: 3/3 - \'c.md\'');
    expect(notices[0]?.hide).toHaveBeenCalledOnce();
  });

  it('should dismiss a single-file operation immediately without leaving a stray notice', () => {
    reporter({ currentPath: 'only.md', processed: 1, total: 1 });
    expect(showNoticeSpy).toHaveBeenCalledExactlyOnceWith('Updating links: 1/1 - \'only.md\'', { isPermanent: true });
    expect(notices).toHaveLength(1);
    expect(notices[0]?.setMessage).not.toHaveBeenCalled();
    expect(notices[0]?.hide).toHaveBeenCalledOnce();
  });

  it('should start a fresh notice for a new operation after the previous one completed', () => {
    reporter({ currentPath: 'a.md', processed: 1, total: 1 });
    reporter({ currentPath: 'b.md', processed: 1, total: 2 });
    reporter({ currentPath: 'c.md', processed: 2, total: 2 });
    expect(showNoticeSpy).toHaveBeenCalledTimes(2);
    expect(notices).toHaveLength(2);
    expect(notices[0]?.hide).toHaveBeenCalledOnce();
    expect(notices[1]?.setMessage).toHaveBeenCalledExactlyOnceWith('Updating links: 2/2 - \'c.md\'');
    expect(notices[1]?.hide).toHaveBeenCalledOnce();
  });
});
