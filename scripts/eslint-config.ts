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
