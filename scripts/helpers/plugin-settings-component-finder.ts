/**
 * @file
 *
 * Finds this plugin's settings component from inside an `evalInObsidian` closure, so a suite edits the settings
 * through `editAndSave` rather than onto the settings object.
 *
 * An in-memory edit does not survive a `data.json` reload: the reload replaces the settings object, so the edit
 * reverts to whatever the file holds, mid-suite and without a trace. `editAndSave` writes the file too, so a
 * reload reads the edit back. The same goes for restoring the prior values at the end of a suite.
 *
 * The finder runs in the renderer. A suite hands it over through `evalInObsidian`'s `input`, which serializes a
 * function by its source text, so it must not reach anything outside its own body — no imports, no module-level
 * constants.
 */

/**
 * The part of the plugin's settings component a suite drives.
 *
 * @typeParam Settings - The slice of the settings the suite reads and edits.
 */
export interface PluginSettingsComponentLike<Settings> {
  /**
   * Edits the settings and saves them to `data.json`.
   *
   * @param settingsEditor - Applies the edit to the settings.
   * @returns A {@link Promise} that resolves once the settings are saved.
   */
  readonly editAndSave: (settingsEditor: (settings: Settings) => void) => Promise<void>;

  /**
   * The live settings. Read them through the component each time: a reload replaces the object.
   */
  readonly settings: Settings;
}

/**
 * Finds the plugin's settings component.
 *
 * The component sits on the plugin's `pluginSettingsComponent` accessor, which is protected in its typings and
 * throws while unset, so it is read defensively.
 *
 * @typeParam Settings - The slice of the settings the suite reads and edits.
 * @param plugin - The plugin instance, as `app.plugins.getPlugin` returns it.
 * @param isSettings - Checks that the settings carry the keys the suite relies on.
 * @returns The settings component, or `null` when the plugin or its settings are not there.
 */
export function findPluginSettingsComponent<Settings>(
  plugin: unknown,
  isSettings: (value: unknown) => value is Settings
): null | PluginSettingsComponentLike<Settings> {
  if (typeof plugin !== 'object' || plugin === null) {
    return null;
  }

  let component: unknown;
  try {
    component = (plugin as Record<string, unknown>)['pluginSettingsComponent'];
  } catch {
    // The accessor throws until the plugin has set its component, which is the not-found answer.
    component = null;
  }

  if (typeof component !== 'object' || component === null) {
    return null;
  }

  const record = component as Record<string, unknown>;
  const isComponent = typeof record['editAndSave'] === 'function' && isSettings(record['settings']);
  return isComponent ? component as PluginSettingsComponentLike<Settings> : null;
}
