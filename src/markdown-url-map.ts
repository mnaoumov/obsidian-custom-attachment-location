export class MarkdownUrlMap {
  private readonly map = new Map<string, string>();

  public delete(path: string): void {
    this.map.delete(path);
  }

  public get(path: string): null | string {
    return this.map.get(path) ?? null;
  }

  public set(path: string, url: string): void {
    this.map.set(path, url);
  }
}
