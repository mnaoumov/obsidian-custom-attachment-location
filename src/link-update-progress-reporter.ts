import type { Notice } from 'obsidian';
import type { PluginNoticeComponent } from 'obsidian-dev-utils/obsidian/components/plugin-notice-component';
import type {
  LinkUpdateProgress,
  LinkUpdateProgressReporter
} from 'obsidian-dev-utils/obsidian/link-update-progress';

import { t } from 'obsidian-dev-utils/obsidian/i18n/i18n';

/**
 * Parameters for {@link createLinkUpdateProgressReporter}.
 */
interface CreateLinkUpdateProgressReporterParams {
  /**
   * The plugin notice component used to show/update the persistent progress notice.
   */
  readonly pluginNoticeComponent: PluginNoticeComponent;
}

/**
 * Creates a {@link LinkUpdateProgressReporter} that surfaces the progress of a multi-file rename/move
 * link-update operation as a single persistent notice updated in place (e.g.
 * `Updating links: 3/10 - 'note.md'`). The notice is created on the first callback, updated on every
 * subsequent callback, and dismissed once every file has been processed, so the user knows exactly when
 * the link updates finish and it is safe to resume vault operations.
 *
 * @param params - See {@link CreateLinkUpdateProgressReporterParams}.
 * @returns A reporter to pass as `linkUpdateProgressReporter` to a `RenameDeleteHandlerComponent`.
 */
export function createLinkUpdateProgressReporter(params: CreateLinkUpdateProgressReporterParams): LinkUpdateProgressReporter {
  const pluginNoticeComponent = params.pluginNoticeComponent;
  let notice: Notice | null = null;

  return (progress: LinkUpdateProgress): void => {
    const message = t(($) => $.notice.updatingLinks, {
      currentPath: progress.currentPath,
      processed: progress.processed,
      total: progress.total
    });

    if (notice) {
      notice.setMessage(message);
    } else {
      notice = pluginNoticeComponent.showNotice(message, {
        isPermanent: true
      });
    }

    if (progress.processed >= progress.total) {
      notice.hide();
      notice = null;
    }
  };
}
