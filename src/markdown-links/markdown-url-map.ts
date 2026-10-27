interface MarkdownUrlMapSetParams {
  readonly path: string;
  readonly url: string;
}

export class MarkdownUrlMap {
  private readonly map = new Map<string, string>();

  public delete(path: string): void {
    this.map.delete(path);
  }

  public get(path: string): null | string {
    return this.map.get(path) ?? null;
  }

  public set(params: MarkdownUrlMapSetParams): void {
    const { path, url } = params;
    this.map.set(path, url);
  }
}
