import { describe, it, expect } from 'vitest'
import { geoNaturalEarth1, geoPath } from 'd3-geo'
import { feature } from 'topojson-client'
import worldTopo from 'world-atlas/countries-110m.json'

describe('WorldMap projection', () => {
  it('projects a known coordinate to viewBox space (0..720, 0..360)', () => {
    const proj = geoNaturalEarth1().fitSize([720, 360], { type: 'Sphere' } as never)
    const [x, y] = proj([0, 0]) ?? []
    expect(x).toBeTypeOf('number')
    expect(y).toBeTypeOf('number')
    expect(x).toBeGreaterThan(0)
    expect(x).toBeLessThan(720)
    expect(y).toBeGreaterThan(0)
    expect(y).toBeLessThan(360)
  })

  it('renders a path for every country feature', () => {
    const fc = feature(worldTopo as never, (worldTopo as any).objects.countries) as unknown as any
    const p = geoPath(geoNaturalEarth1().fitSize([720, 360], { type: 'Sphere' } as never))
    for (const f of fc.features) {
      const d = p(f)
      expect(d).toBeTypeOf('string')
      expect((d as string).length).toBeGreaterThan(0)
    }
  })

  it('handles sphere outline without throwing', () => {
    const p = geoPath(geoNaturalEarth1().fitSize([720, 360], { type: 'Sphere' } as never))
    expect(() => p({ type: 'Sphere' } as never)).not.toThrow()
  })
})
