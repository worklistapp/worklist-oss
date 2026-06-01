import { PlaintextCache } from '../strong-box-cache'
import { afterEach, describe, expect, it, vi } from 'vitest'

describe('PlaintextCache', () => {
  afterEach(() => {
    vi.useRealTimers()
  })

  it('returns cached entries before ttl expires', () => {
    const cache = new PlaintextCache(2, 1000)
    const key = 'entry'
    const data = new Uint8Array([1, 2, 3])

    cache.set(key, data)
    const result = cache.get(key)

    expect(result).toEqual(data)
    expect(result).not.toBe(data)
  })

  it('evicts expired entries', () => {
    vi.useFakeTimers()
    const cache = new PlaintextCache(2, 10)
    cache.set('old', new Uint8Array([0]))

    vi.advanceTimersByTime(15)
    expect(cache.get('old')).toBeNull()
  })

  it('evicts least recently used when capacity exceeded', () => {
    const cache = new PlaintextCache(2, 1000)
    cache.set('first', new Uint8Array([1]))
    cache.set('second', new Uint8Array([2]))

    // Access first so second becomes LRU
    expect(cache.get('first')).not.toBeNull()

    cache.set('third', new Uint8Array([3]))

    expect(cache.get('second')).toBeNull()
    expect(cache.get('first')).not.toBeNull()
    expect(cache.get('third')).not.toBeNull()
  })
})
