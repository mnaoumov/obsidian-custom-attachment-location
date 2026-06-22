export class ImageSizeMap {
  private readonly map = new Map<string, string>();

  public getAndDelete(path: string): null | string {
    const size = this.map.get(path) ?? null;
    if (size) {
      this.map.delete(path);
    }
    return size;
  }

  public set(path: string, size: string): void {
    this.map.set(path, size);
  }
}
