import { useState } from 'react'
import { Download, FileSpreadsheet, Check, Loader2 } from 'lucide-react'
import { Button } from './Button'
import { cn } from '@/lib/utils'

interface ExportButtonProps<T> {
  data: T[]
  filename: string
  headers: { key: keyof T | ((item: T) => string); label: string }[]
  className?: string
  variant?: 'default' | 'outline' | 'ghost'
  size?: 'default' | 'sm' | 'lg'
}

export function ExportButton<T extends Record<string, unknown>>({
  data,
  filename,
  headers,
  className,
  variant = 'outline',
  size = 'default',
}: ExportButtonProps<T>) {
  const [isExporting, setIsExporting] = useState(false)
  const [exported, setExported] = useState(false)

  const escapeCSVField = (value: unknown): string => {
    if (value === null || value === undefined) return ''
    const stringValue = String(value)
    // Escape quotes and wrap in quotes if contains comma, newline, or quote
    if (stringValue.includes(',') || stringValue.includes('\n') || stringValue.includes('"')) {
      return `"${stringValue.replace(/"/g, '""')}"`
    }
    return stringValue
  }

  const exportToCSV = async () => {
    setIsExporting(true)

    try {
      // Generate CSV content
      const headerRow = headers.map((h) => escapeCSVField(h.label)).join(',')
      
      const dataRows = data.map((item) =>
        headers
          .map((h) => {
            const value = typeof h.key === 'function' ? h.key(item) : item[h.key]
            return escapeCSVField(value)
          })
          .join(',')
      )

      const csvContent = [headerRow, ...dataRows].join('\n')

      // Create and download file
      const blob = new Blob(['\ufeff' + csvContent], { type: 'text/csv;charset=utf-8;' })
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = `${filename}-${new Date().toISOString().split('T')[0]}.csv`
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
      URL.revokeObjectURL(url)

      setExported(true)
      setTimeout(() => setExported(false), 2000)
    } catch (error) {
      console.error('Export failed:', error)
    } finally {
      setIsExporting(false)
    }
  }

  return (
    <Button
      variant={variant}
      size={size}
      onClick={exportToCSV}
      disabled={isExporting || data.length === 0}
      className={cn('gap-2', className)}
    >
      {isExporting ? (
        <>
          <Loader2 className="h-4 w-4 animate-spin" />
          Exporting...
        </>
      ) : exported ? (
        <>
          <Check className="h-4 w-4" />
          Exported!
        </>
      ) : (
        <>
          <Download className="h-4 w-4" />
          Export CSV
        </>
      )}
    </Button>
  )
}

interface ExportMenuProps<T> {
  data: T[]
  filename: string
  headers: { key: keyof T | ((item: T) => string); label: string }[]
  className?: string
}

export function ExportMenu<T extends Record<string, unknown>>({
  data,
  filename,
  headers,
  className,
}: ExportMenuProps<T>) {
  const [showMenu, setShowMenu] = useState(false)

  const exportToCSV = () => {
    const escapeCSVField = (value: unknown): string => {
      if (value === null || value === undefined) return ''
      const stringValue = String(value)
      if (stringValue.includes(',') || stringValue.includes('\n') || stringValue.includes('"')) {
        return `"${stringValue.replace(/"/g, '""')}"`
      }
      return stringValue
    }

    const headerRow = headers.map((h) => escapeCSVField(h.label)).join(',')
    const dataRows = data.map((item) =>
      headers
        .map((h) => {
          const value = typeof h.key === 'function' ? h.key(item) : item[h.key]
          return escapeCSVField(value)
        })
        .join(',')
    )

    const csvContent = [headerRow, ...dataRows].join('\n')
    const blob = new Blob(['\ufeff' + csvContent], { type: 'text/csv;charset=utf-8;' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `${filename}-${new Date().toISOString().split('T')[0]}.csv`
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
    URL.revokeObjectURL(url)
    setShowMenu(false)
  }

  const exportToJSON = () => {
    const jsonContent = JSON.stringify(data, null, 2)
    const blob = new Blob([jsonContent], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `${filename}-${new Date().toISOString().split('T')[0]}.json`
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
    URL.revokeObjectURL(url)
    setShowMenu(false)
  }

  return (
    <div className={cn('relative', className)}>
      <Button
        variant="outline"
        onClick={() => setShowMenu(!showMenu)}
        disabled={data.length === 0}
        className="gap-2"
      >
        <Download className="h-4 w-4" />
        Export
      </Button>

      {showMenu && (
        <div className="absolute right-0 top-full mt-1 w-40 rounded-md border bg-popover shadow-md z-50">
          <div className="p-1">
            <button
              onClick={exportToCSV}
              className="w-full flex items-center gap-2 px-3 py-2 text-sm rounded-sm hover:bg-accent transition-colors"
            >
              <FileSpreadsheet className="h-4 w-4" />
              Export as CSV
            </button>
            <button
              onClick={exportToJSON}
              className="w-full flex items-center gap-2 px-3 py-2 text-sm rounded-sm hover:bg-accent transition-colors"
            >
              <Download className="h-4 w-4" />
              Export as JSON
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
