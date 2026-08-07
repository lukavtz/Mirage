import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { I18nProvider } from '@/lib/i18n'
import DocsPage from './DocsPage'
import { api } from '@/lib/api'

vi.mock('@/lib/api', () => ({
  api: { get: vi.fn(), post: vi.fn(), put: vi.fn(), del: vi.fn(), fetchCsrf: vi.fn(), clearCsrf: vi.fn() },
}))

const DOC_LIST = { docs: [
  { path: 'getting-started', title: 'Getting Started' },
  { path: 'advanced', title: 'Advanced' },
] }

const MARKDOWN = [
  '# Overview',
  '## Details',
  '### Deep dive',
  '| Name | Value |',
  '|------|-------|',
  '| Alpha | 1 |',
  '| Beta | 2 |',
  '- first item',
  'Some **bold** text',
  '',
  'plain line',
].join('\n')

function mockApi(list = DOC_LIST) {
  vi.mocked(api.get).mockImplementation((path: string) => {
    if (path === '/api/docs') return Promise.resolve(list)
    if (path === '/api/docs/getting-started') {
      return Promise.resolve({ title: 'Getting Started', content: MARKDOWN })
    }
    if (path === '/api/docs/advanced') {
      return Promise.resolve({ title: 'Advanced Guide', content: '# Advanced\n\nAdvanced content here' })
    }
    return Promise.resolve({})
  })
}

function renderDocs(initialPath = '/docs') {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <I18nProvider>
        <MemoryRouter initialEntries={[initialPath]}>
          <Routes>
            <Route path="/docs" element={<DocsPage />} />
            <Route path="/docs/:path" element={<DocsPage />} />
          </Routes>
        </MemoryRouter>
      </I18nProvider>
    </QueryClientProvider>
  )
}

describe('DocsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('auto-navigates to the first doc and renders its markdown content', async () => {
    mockApi()
    renderDocs('/docs')

    // sidebar with both docs
    expect(await screen.findByText('Getting Started')).toBeInTheDocument()
    expect(screen.getByText('Advanced')).toBeInTheDocument()

    // markdown rendering: headings, table, list, bold
    const overview = await screen.findByText('Overview')
    expect(overview.tagName).toBe('H1')
    expect(screen.getByText('Details').tagName).toBe('H2')
    expect(screen.getByText('Deep dive').tagName).toBe('H3')
    expect(screen.getByText('Alpha')).toBeInTheDocument()
    expect(screen.getByText('1')).toBeInTheDocument()
    expect(screen.getByText('first item').tagName).toBe('LI')
    expect(document.querySelector('strong')?.textContent).toBe('bold')
    expect(screen.getByText('plain line')).toBeInTheDocument()
  })

  it('renders doc content for a direct deep link', async () => {
    mockApi()
    renderDocs('/docs/advanced')

    expect(await screen.findByText('Advanced Guide')).toBeInTheDocument()
    expect(screen.getByText('Advanced', { selector: 'h1' })).toBeInTheDocument()
    expect(screen.getByText('Advanced content here')).toBeInTheDocument()
  })

  it('navigates between docs when a sidebar button is clicked', async () => {
    mockApi()
    renderDocs('/docs/getting-started')

    expect(await screen.findByText('Overview')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Advanced' }))

    expect(await screen.findByText('Advanced Guide')).toBeInTheDocument()
    expect(screen.getByText('Advanced content here')).toBeInTheDocument()
  })

  it('filters the doc list via search and shows no-results state', async () => {
    mockApi()
    renderDocs('/docs/getting-started')

    await screen.findByText('Overview')
    const searchInput = screen.getByPlaceholderText('Search docs...')

    fireEvent.change(searchInput, { target: { value: 'zzz' } })
    expect(screen.getByText('No docs found')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Getting Started' })).not.toBeInTheDocument()

    fireEvent.change(searchInput, { target: { value: 'adv' } })
    expect(screen.getByRole('button', { name: 'Advanced' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Getting Started' })).not.toBeInTheDocument()
  })

  it('shows the loading state while fetching doc content', async () => {
    vi.mocked(api.get).mockImplementation((path: string) => {
      if (path === '/api/docs') return Promise.resolve(DOC_LIST)
      const { promise } = Promise.withResolvers<{ title: string; content: string }>()
      return promise
    })
    renderDocs('/docs/getting-started')

    expect(await screen.findByText('Loading...')).toBeInTheDocument()
    expect(document.querySelectorAll('.animate-pulse').length).toBeGreaterThan(0)
  })

  it('shows the select prompt when no doc list is available', async () => {
    vi.mocked(api.get).mockResolvedValue({ docs: [] })
    renderDocs('/docs')

    expect(await screen.findByText('Select a document from the sidebar')).toBeInTheDocument()
  })
})
