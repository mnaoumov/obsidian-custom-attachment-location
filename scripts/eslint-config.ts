import type { Linter } from 'eslint';

import { defineConfig } from 'eslint/config';
import { ObsidianPluginRepoPaths } from 'obsidian-dev-utils/obsidian/plugin/obsidian-plugin-repo-paths';
import { defineEslintConfigs } from 'obsidian-dev-utils/script-utils/linters/eslint-config';

export const configs: Linter.Config[] = defineEslintConfigs({
  customConfigs() {
    return defineConfig([
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
          'src/patches/write-attribution-patch-component.test.ts',
          'src/externally-created-attachment-plugin-list.desktop.integration.test.ts'
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
          'obsidian-dev-utils/manifest-id': 'off'
        }
      }
    ]);
  }
});
