import { MonkeyAroundComponent } from 'obsidian-dev-utils/obsidian/components/monkey-around-component';

interface FileEx {
  path: string;
}

interface WebUtilsGetPathForFilePatchComponentConstructorParams {
  readonly webUtils: Electron.WebUtils;
}

export class WebUtilsGetPathForFilePatchComponent extends MonkeyAroundComponent {
  private readonly webUtils: Electron.WebUtils;

  public constructor(params: WebUtilsGetPathForFilePatchComponentConstructorParams) {
    super();
    this.webUtils = params.webUtils;
  }

  public override onload(): void {
    this.registerMethodPatch({
      methodName: 'getPathForFile',
      obj: this.webUtils,
      patchHandler: ({
        fallback,
        originalArgs: [file]
      }) => {
        const fileEx = file as Partial<FileEx>;
        if (fileEx.path) {
          return fileEx.path;
        }
        return fallback();
      }
    });
  }
}
