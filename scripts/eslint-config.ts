import type { Linter } from 'eslint';

import { defineEslintConfigs } from '@mnaoumov/obsidian-dev-toolkit/linters/eslint-config';
import { ObsidianPluginRepoPaths } from '@mnaoumov/obsidian-dev-toolkit/obsidian-plugin-repo-paths';
import {
  defineConfig,
  globalIgnores
} from 'eslint/config';

export const configs: Linter.Config[] = defineEslintConfigs({
  customConfigs() {
    return defineConfig([
      // A verbatim copy of the provider's hand-written `api.d.ts`, refreshed from its repository rather than edited,
      // so its style is the provider's to keep.
      globalIgnores(['src/advanced-rename-and-delete-handler/api/api.d.ts']),
      {
        rules: {
          'obsidianmd/ui/sentence-case': [
            'error',
            {
              brands: [
                'Backlink Cache',
                'Show Hidden Files'
              ]
            }
          ]
        }
      },
      {
        files: [
          'src/externally-created-attachments/write-attribution-patch-component.test.ts',
          'src/externally-created-attachments/externally-created-attachment-plugin-list.desktop.integration.test.ts'
        ],
        rules: {
          /**
           * These two suites test how the plugin identifies WHICH other plugin wrote a file, and the only
           * answer Obsidian offers is the `plugin:<id>` source URL it stamps on a community plugin's code:
           * `window.eval('(function anonymous(...){...})\n//# sourceURL=plugin:' + id)`. Reproducing that
           * compilation is the only way to produce the stack frames a real plugin produces, so it is the
           * one thing these tests cannot mock away without testing nothing.
           *
           * Waived at file scope rather than inline because `no-eval` and `obsidianmd/rule-custom-message`
           * are on the no-inline-disable list. The risk the rules guard against is absent here: the
           * compiled source is a literal in these files, and neither file ships — no `*.test.ts` is
           * bundled into `main.js`. Production code never compiles a string; it only READS the frames.
           */
          '@typescript-eslint/no-implied-eval': 'off',
          'no-new-func': 'off',
          'obsidianmd/rule-custom-message': 'off'
        }
      },
      {
        files: [ObsidianPluginRepoPaths.ManifestJson],
        rules: {
          /**
           * The community directory forbids `obsidian` inside a plugin `id`, and this one carries it.
           * A published `id` is permanent — changing it orphans every existing installation and the
           * listing itself — so this repo can never satisfy the rule. The other three manifest rules
           * stay on, which is why the checks are separate rules rather than one.
           */
          'obsidian-dev-toolkit/manifest-id': 'off'
        }
      }
    ]);
  }
});
