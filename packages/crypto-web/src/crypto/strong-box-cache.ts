export class PlaintextCache {
  private readonly entries = new Map<string, CacheEntry>()
  private readonly maxEntries: number
  private readonly ttlMs: number

  constructor(maxEntries = 64, ttlMs = 120_000) {
    this.maxEntries = maxEntries
    this.ttlMs = ttlMs
  }

  get(key: string): Uint8Array | null {
    const entry = this.entries.get(key)
    if (!entry) {
      return null
    }

    const now = Date.now()
    if (entry.expiresAt <= now) {
      this.entries.delete(key)
      return null
    }

    this.entries.delete(key)
    this.entries.set(key, { value: entry.value, expiresAt: now + this.ttlMs })
    return entry.value.slice()
  }

  set(key: string, value: Uint8Array) {
    const copy = value.slice()
    if (this.entries.has(key)) {
      this.entries.delete(key)
    }
    this.entries.set(key, {
      value: copy,
      expiresAt: Date.now() + this.ttlMs,
    })

    if (this.entries.size > this.maxEntries) {
      this.evict()
    }
  }

  clear() {
    this.entries.clear()
  }

  private evict() {
    const iterator = this.entries.keys().next()
    if (!iterator.done) {
      this.entries.delete(iterator.value)
    }
  }
}

type CacheEntry = {
  value: Uint8Array
  expiresAt: number
}
