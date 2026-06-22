import type {
  App,
  TFile
} from 'obsidian';
import type { CanvasData } from 'obsidian/canvas.js';

import { strictProxy } from 'obsidian-dev-utils/strict-proxy';
import {
  describe,
  expect,
  it,
  vi
} from 'vitest';

import { getCanvasLinks } from './canvas-links.ts';

function createApp(canvasData: CanvasData): App {
  return strictProxy<App>({
    vault: strictProxy<App['vault']>({
      readJson: vi.fn<App['vault']['readJson']>().mockResolvedValue(canvasData)
    })
  });
}

describe('getCanvasLinks', () => {
  it('should return a reference cache for each file node', async () => {
    const canvasData: CanvasData = {
      edges: [],
      nodes: [
        { file: 'attachments/image.png', height: 0, id: 'a', type: 'file', width: 0, x: 0, y: 0 },
        { file: 'notes/linked.md', height: 0, id: 'b', type: 'file', width: 0, x: 0, y: 0 }
      ]
    };
    const app = createApp(canvasData);
    const canvasFile = strictProxy<TFile>({ path: 'board.canvas' });

    const result = await getCanvasLinks(app, canvasFile);

    expect(app.vault.readJson).toHaveBeenCalledWith('board.canvas');
    expect(result).toStrictEqual([
      {
        link: 'attachments/image.png',
        original: 'attachments/image.png',
        position: {
          end: { col: 0, line: 0, loc: 0, offset: 0 },
          start: { col: 0, line: 0, loc: 0, offset: 0 }
        }
      },
      {
        link: 'notes/linked.md',
        original: 'notes/linked.md',
        position: {
          end: { col: 0, line: 0, loc: 0, offset: 0 },
          start: { col: 0, line: 0, loc: 0, offset: 0 }
        }
      }
    ]);
  });

  it('should ignore non-file nodes', async () => {
    const canvasData: CanvasData = {
      edges: [],
      nodes: [
        { height: 0, id: 'a', text: 'plain text', type: 'text', width: 0, x: 0, y: 0 },
        { file: 'notes/kept.md', height: 0, id: 'b', type: 'file', width: 0, x: 0, y: 0 },
        { height: 0, id: 'c', type: 'link', url: 'https://example.com', width: 0, x: 0, y: 0 }
      ]
    };
    const app = createApp(canvasData);
    const canvasFile = strictProxy<TFile>({ path: 'board.canvas' });

    const result = await getCanvasLinks(app, canvasFile);

    expect(result).toHaveLength(1);
    expect(result[0]?.link).toBe('notes/kept.md');
  });

  it('should return an empty array when there are no nodes', async () => {
    const app = createApp({ edges: [], nodes: [] });
    const canvasFile = strictProxy<TFile>({ path: 'empty.canvas' });

    const result = await getCanvasLinks(app, canvasFile);

    expect(result).toStrictEqual([]);
  });
});
