import type { TAbstractFile } from 'obsidian';

/**
 * Builds the one-line summary a bulk command's git commit is titled with, naming the command and what it ran on.
 *
 * English on purpose, whatever the interface language: the summary is a commit subject, read in `git log` by whoever
 * shares the repository, and the same operation must read the same on every machine.
 *
 * @param commandName - What the command does, such as `Collect attachments`.
 * @param abstractFiles - The notes and folders the command ran on. The vault root, or none, reads as the entire vault.
 * @returns The summary, such as `Collect attachments in Notes/a.md and 2 more`.
 */
export function buildBulkOperationSummary(commandName: string, abstractFiles: readonly TAbstractFile[] = []): string {
  const [first] = abstractFiles;
  if (!first || abstractFiles.some((abstractFile) => abstractFile.path === '/')) {
    return `${commandName} in entire vault`;
  }

  const moreCount = abstractFiles.length - 1;
  return moreCount === 0 ? `${commandName} in ${first.path}` : `${commandName} in ${first.path} and ${String(moreCount)} more`;
}
