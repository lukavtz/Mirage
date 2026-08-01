import { useEffect, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Book, Search, ChevronRight } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import { api } from '@/lib/api'
import { cn } from '@/lib/utils'

interface DocFile {
  path: string
  title: string
}

interface DocContent {
  content: string
  title: string
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;')
}

function renderMarkdown(md: string): string {
  let html = ''
  const lines = md.split('\n')
  let inTable = false
  html += '<div class="text-sm text-foreground/90 leading-relaxed max-w-none [&_h1]:text-2xl [&_h1]:font-bold [&_h1]:mb-4 [&_h1]:mt-6 [&_h1:first-child]:mt-0 [&_h2]:text-xl [&_h2]:font-semibold [&_h2]:mb-3 [&_h2]:mt-5 [&_h3]:text-lg [&_h3]:font-medium [&_h3]:mb-2 [&_h3]:mt-4 [&_p]:mb-3 [&_code]:bg-muted [&_code]:px-1.5 [&_code]:py-0.5 [&_code]:rounded [&_code]:text-xs [&_code]:font-mono [&_pre]:bg-muted [&_pre]:p-4 [&_pre]:rounded-lg [&_pre]:overflow-x-auto [&_pre]:mb-4 [&_pre_code]:bg-transparent [&_pre_code]:p-0 [&_ul]:list-disc [&_ul]:pl-6 [&_ul]:mb-3 [&_ol]:list-decimal [&_ol]:pl-6 [&_ol]:mb-3 [&_li]:mb-1 [&_a]:text-primary [&_a]:underline [&_a]:underline-offset-2 [&_blockquote]:border-l-4 [&_blockquote]:border-primary/30 [&_blockquote]:pl-4 [&_blockquote]:italic [&_blockquote]:text-muted-foreground [&_blockquote]:mb-3 [&_strong]:font-semibold [&_em]:italic">'
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]

    if (line.startsWith('# ')) {
      html += `<h1 class="text-2xl font-bold mb-4 mt-6 first:mt-0">${escapeHtml(line.slice(2))}</h1>`
    } else if (line.startsWith('## ')) {
      html += `<h2 class="text-xl font-semibold mb-3 mt-5">${escapeHtml(line.slice(3))}</h2>`
    } else if (line.startsWith('### ')) {
      html += `<h3 class="text-lg font-medium mb-2 mt-4">${escapeHtml(line.slice(4))}</h3>`
    } else if (line.startsWith('| ')) {
      if (!inTable) {
        inTable = true
        html += '<table class="min-w-full border-collapse mb-4 text-sm"><tbody>'
      }
      const cells = line.split('|').filter(c => c.trim())
      const isHeader = lines[i + 1]?.startsWith('|---') || lines[i + 1]?.startsWith('|:---')
      const tag = isHeader ? 'th' : 'td'
      html += '<tr>'
      for (const cell of cells) {
        html += `<${tag} class="border border-border px-3 py-1.5">${escapeHtml(cell.trim())}</${tag}>`
      }
      html += '</tr>'
    } else if (line.startsWith('---') && inTable) {
      // skip separator row
    } else {
      if (inTable) {
        inTable = false
        html += '</tbody></table>'
      }
      if (line.trim() === '') {
        html += '<div class="h-2"></div>'
      } else if (line.startsWith('- ')) {
        html += `<li class="ml-4 text-sm text-muted-foreground">${escapeHtml(line.slice(2))}</li>`
      } else if (line.includes('**')) {
        const escaped = escapeHtml(line)
        const rendered = escaped.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
        html += `<p class="text-sm text-muted-foreground mb-1">${rendered}</p>`
      } else {
        html += `<p class="text-sm text-muted-foreground mb-1">${escapeHtml(line)}</p>`
      }
    }
  }
  if (inTable) html += '</tbody></table>'
  html += '</div>'
  return html
}

export default function DocsPage() {
  const { path: docPath } = useParams()
  const navigate = useNavigate()
  const [search, setSearch] = useState('')

  const docListQuery = useQuery({
    queryKey: ['docs'],
    queryFn: () => api.get<{ docs: DocFile[] }>('/api/docs'),
  })
  const docList = docListQuery.data?.docs ?? []

  const docContentQuery = useQuery({
    queryKey: ['docs', docPath],
    queryFn: () => api.get<DocContent>(`/api/docs/${docPath}`),
    enabled: !!docPath,
  })
  const docContent = docContentQuery.data ?? null
  const loading = docContentQuery.isLoading

  useEffect(() => {
    if (!docPath && docList.length > 0 && !docListQuery.isLoading) {
      navigate(`/docs/${docList[0].path}`, { replace: true })
    }
  }, [docPath, docList, docListQuery.isLoading, navigate])

  const filtered = docList.filter(d =>
    d.title.toLowerCase().includes(search.toLowerCase())
  )

  return (
    <div className="flex gap-6 h-[calc(100vh-7rem)]">
      <Card className="w-64 shrink-0 overflow-hidden flex flex-col">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <Book className="h-4 w-4" />
            Documentation
          </CardTitle>
          <div className="relative mt-2">
            <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
            <Input
              placeholder="Search docs..."
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="pl-7 h-8 text-xs"
            />
          </div>
        </CardHeader>
        <CardContent className="flex-1 overflow-y-auto pt-0">
          <nav className="space-y-0.5">
            {filtered.map(doc => (
              <button
                key={doc.path}
                onClick={() => navigate(`/docs/${doc.path}`)}
                className={cn(
                  'w-full text-left px-2 py-1.5 rounded text-xs transition-colors flex items-center gap-1.5',
                  docPath === doc.path
                    ? 'bg-primary/10 text-primary font-medium'
                    : 'text-muted-foreground hover:text-foreground hover:bg-accent'
                )}
              >
                <ChevronRight className={cn(
                  'h-3 w-3 shrink-0 transition-transform',
                  docPath === doc.path && 'rotate-90'
                )} />
                {doc.title}
              </button>
            ))}
          </nav>
          {filtered.length === 0 && (
            <p className="text-xs text-muted-foreground text-center mt-4">No docs found</p>
          )}
        </CardContent>
      </Card>

      <Card className="flex-1 overflow-hidden flex flex-col">
        <CardHeader className="border-b pb-3">
          <CardTitle className="text-sm font-medium">
            {loading ? 'Loading...' : docContent?.title || 'Documentation'}
          </CardTitle>
        </CardHeader>
        <CardContent className="flex-1 overflow-y-auto pt-4">
          {loading ? (
            <div className="space-y-3">
              <Skeleton className="h-6 w-48" />
              <Skeleton className="h-4 w-full" />
              <Skeleton className="h-4 w-3/4" />
              <Skeleton className="h-4 w-5/6" />
              <Skeleton className="h-4 w-2/3" />
            </div>
          ) : docContent ? (
            <div dangerouslySetInnerHTML={{ __html: renderMarkdown(docContent.content) }} />
          ) : (
            <div className="flex items-center justify-center h-full text-muted-foreground text-sm">
              Select a document from the sidebar
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
