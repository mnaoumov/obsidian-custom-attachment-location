// @vitest-environment jsdom

import type { App as AppOriginal } from 'obsidian';

import { ButtonComponent } from 'obsidian';
import { castTo } from 'obsidian-dev-utils/object-utils';
import { initI18N } from 'obsidian-dev-utils/obsidian/i18n/i18n';
import { MinimizableModal } from 'obsidian-dev-utils/obsidian/modals/minimizable-modal';
import { App } from 'obsidian-test-mocks/obsidian';
import {
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import { translationsMap } from '../i18n/locales/translations-map.ts';
import { confirmMinimizable } from './minimizable-confirm-modal.ts';

/*
 * Button handlers live on the component instance rather than on the DOM node, so they are captured as they
 * are registered, the same way the other modal tests press their buttons.
 */

let app: AppOriginal;
let buttonHandlers: Map<ButtonComponent, (mouseEvent: MouseEvent) => unknown>;

beforeAll(async () => {
  await initI18N(translationsMap);
});

beforeEach(() => {
  app = App.createConfigured__().asOriginalType__();
  buttonHandlers = new Map<ButtonComponent, (mouseEvent: MouseEvent) => unknown>();
  vi.spyOn(ButtonComponent.prototype, 'onClick').mockImplementation(function onClickMock(this: ButtonComponent, callback: (mouseEvent: MouseEvent) => unknown): ButtonComponent {
    buttonHandlers.set(this, callback);
    return this;
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

function createMessage(): DocumentFragment {
  return createFragment((f) => {
    f.appendText('About to delete ');
    f.createEl('a', { text: 'assets/image.png' });
    f.createSpan({ text: 'Trash.' });
  });
}

function getButton(buttonText: string): ButtonComponent {
  for (const buttonComponent of buttonHandlers.keys()) {
    if (buttonComponent.buttonEl.textContent === buttonText) {
      return buttonComponent;
    }
  }

  throw new Error(`The dialog has no "${buttonText}" button`);
}

function pressButton(buttonText: string): void {
  for (const [buttonComponent, handler] of buttonHandlers) {
    if (buttonComponent.buttonEl.textContent === buttonText) {
      handler(castTo<MouseEvent>({}));
      return;
    }
  }

  throw new Error(`The dialog has no "${buttonText}" button`);
}

describe('confirmMinimizable', () => {
  it('should resolve true when OK is pressed', async () => {
    const promise = confirmMinimizable({ app, message: createMessage(), okButtonText: 'Delete', title: 'Delete unused attachments' });
    pressButton('Delete');
    await expect(promise).resolves.toBe(true);
  });

  it('should resolve false when Cancel is pressed', async () => {
    const promise = confirmMinimizable({ app, cancelButtonText: 'Keep', message: createMessage() });
    pressButton('Keep');
    await expect(promise).resolves.toBe(false);
  });

  it('should default the button texts to the library ones', async () => {
    const promise = confirmMinimizable({ app, message: 'plain' });
    expect(buttonHandlers.size).toBe(2);
    pressButton('Cancel');
    await expect(promise).resolves.toBe(false);
  });

  it('should mark its buttons with the classes the confirm dialog uses', async () => {
    const promise = confirmMinimizable({ app, cancelButtonText: 'Keep', message: 'plain', okButtonText: 'Delete' });
    expect(getButton('Delete').buttonEl.hasClass('ok-button')).toBe(true);
    expect(getButton('Keep').buttonEl.hasClass('cancel-button')).toBe(true);
    pressButton('Keep');
    await promise;
  });

  it('should render the title and the message', async () => {
    const minimizeSpy = vi.spyOn(MinimizableModal.prototype, 'minimize');
    const promise = confirmMinimizable({ app, cancelButtonText: 'Keep', message: createMessage(), title: 'Delete unused attachments' });
    const contentEl = getButton('Keep').buttonEl.parentElement;
    expect(contentEl?.textContent).toContain('About to delete assets/image.pngTrash.');
    expect(contentEl?.parentElement?.textContent).toContain('Delete unused attachments');
    expect(minimizeSpy).not.toHaveBeenCalled();
    pressButton('Keep');
    await promise;
  });

  it('should minimize itself when a link in the message is clicked', async () => {
    const minimizeSpy = vi.spyOn(MinimizableModal.prototype, 'minimize').mockImplementation(vi.fn());
    const promise = confirmMinimizable({ app, cancelButtonText: 'Keep', message: createMessage() });
    const contentEl = getButton('Keep').buttonEl.parentElement;

    contentEl?.querySelector('a')?.click();

    expect(minimizeSpy).toHaveBeenCalledOnce();
    pressButton('Keep');
    await promise;
  });

  it('should stay put when anything other than a link is clicked', async () => {
    const minimizeSpy = vi.spyOn(MinimizableModal.prototype, 'minimize').mockImplementation(vi.fn());
    const promise = confirmMinimizable({ app, cancelButtonText: 'Keep', message: createMessage() });
    const contentEl = getButton('Keep').buttonEl.parentElement;

    contentEl?.querySelector('span')?.click();
    contentEl?.dispatchEvent(new Event('click'));
    // A text node is an event target too, and has no `closest` to ask.
    contentEl?.querySelector('p')?.firstChild?.dispatchEvent(new Event('click', { bubbles: true }));

    expect(minimizeSpy).not.toHaveBeenCalled();
    pressButton('Keep');
    await promise;
  });
});
