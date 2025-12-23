import { useState, useRef, useEffect } from 'react'
import { Filter, X, ChevronDown } from 'lucide-react'
import { Button } from './Button'
import { Badge } from './Badge'
import { cn } from '@/lib/utils'

export interface FilterOption {
  label: string
  value: string
}

export interface FilterConfig {
  key: string
  label: string
  type: 'select' | 'multiselect' | 'date-range'
  options?: FilterOption[]
}

export interface ActiveFilter {
  key: string
  value: string | string[]
  label: string
}

interface FilterBarProps {
  filters: FilterConfig[]
  activeFilters: Record<string, string | string[]>
  onFilterChange: (key: string, value: string | string[] | null) => void
  onClearAll: () => void
  className?: string
}

export function FilterBar({
  filters,
  activeFilters,
  onFilterChange,
  onClearAll,
  className,
}: FilterBarProps) {
  const [openDropdown, setOpenDropdown] = useState<string | null>(null)
  const dropdownRef = useRef<HTMLDivElement>(null)

  // Close dropdown when clicking outside
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setOpenDropdown(null)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  const activeFilterCount = Object.values(activeFilters).filter(
    (v) => v !== null && v !== '' && (!Array.isArray(v) || v.length > 0)
  ).length

  const getFilterLabel = (filter: FilterConfig, value: string | string[]) => {
    if (Array.isArray(value)) {
      return `${filter.label}: ${value.length} selected`
    }
    const option = filter.options?.find((o) => o.value === value)
    return option ? option.label : value
  }

  return (
    <div className={cn('flex flex-col gap-2', className)} ref={dropdownRef}>
      <div className="flex flex-wrap items-center gap-2">
        <div className="flex items-center gap-1 text-sm text-muted-foreground">
          <Filter className="h-4 w-4" />
          <span>Filters:</span>
        </div>

        {filters.map((filter) => (
          <div key={filter.key} className="relative">
            <Button
              variant={activeFilters[filter.key] ? 'default' : 'outline'}
              size="sm"
              onClick={() => setOpenDropdown(openDropdown === filter.key ? null : filter.key)}
              className="gap-1"
            >
              {filter.label}
              <ChevronDown className={cn('h-4 w-4 transition-transform', openDropdown === filter.key && 'rotate-180')} />
            </Button>

            {/* Dropdown */}
            {openDropdown === filter.key && filter.type === 'select' && (
              <div className="absolute z-50 top-full left-0 mt-1 w-48 rounded-md border bg-popover shadow-md">
                <div className="p-1">
                  <button
                    className={cn(
                      'w-full text-left px-3 py-2 text-sm rounded-sm hover:bg-accent transition-colors',
                      !activeFilters[filter.key] && 'bg-accent'
                    )}
                    onClick={() => {
                      onFilterChange(filter.key, null)
                      setOpenDropdown(null)
                    }}
                  >
                    All
                  </button>
                  {filter.options?.map((option) => (
                    <button
                      key={option.value}
                      className={cn(
                        'w-full text-left px-3 py-2 text-sm rounded-sm hover:bg-accent transition-colors',
                        activeFilters[filter.key] === option.value && 'bg-accent'
                      )}
                      onClick={() => {
                        onFilterChange(filter.key, option.value)
                        setOpenDropdown(null)
                      }}
                    >
                      {option.label}
                    </button>
                  ))}
                </div>
              </div>
            )}

            {/* Multi-select Dropdown */}
            {openDropdown === filter.key && filter.type === 'multiselect' && (
              <div className="absolute z-50 top-full left-0 mt-1 w-48 rounded-md border bg-popover shadow-md">
                <div className="p-1 max-h-64 overflow-auto">
                  {filter.options?.map((option) => {
                    const values = activeFilters[filter.key] as string[] || []
                    const isSelected = values.includes(option.value)
                    return (
                      <label
                        key={option.value}
                        className="flex items-center gap-2 px-3 py-2 text-sm rounded-sm hover:bg-accent cursor-pointer"
                      >
                        <input
                          type="checkbox"
                          checked={isSelected}
                          onChange={() => {
                            const newValues = isSelected
                              ? values.filter((v) => v !== option.value)
                              : [...values, option.value]
                            onFilterChange(filter.key, newValues.length > 0 ? newValues : null)
                          }}
                          className="rounded border-input"
                        />
                        {option.label}
                      </label>
                    )
                  })}
                </div>
              </div>
            )}
          </div>
        ))}

        {activeFilterCount > 0 && (
          <Button variant="ghost" size="sm" onClick={onClearAll} className="gap-1 text-muted-foreground">
            <X className="h-4 w-4" />
            Clear all
          </Button>
        )}
      </div>

      {/* Active filters display */}
      {activeFilterCount > 0 && (
        <div className="flex flex-wrap gap-2">
          {Object.entries(activeFilters).map(([key, value]) => {
            if (!value || (Array.isArray(value) && value.length === 0)) return null
            const filter = filters.find((f) => f.key === key)
            if (!filter) return null

            return (
              <Badge key={key} variant="secondary" className="gap-1 pr-1">
                {getFilterLabel(filter, value)}
                <button
                  onClick={() => onFilterChange(key, null)}
                  className="ml-1 rounded-full p-0.5 hover:bg-muted"
                  aria-label={`Remove ${filter.label} filter`}
                >
                  <X className="h-3 w-3" />
                </button>
              </Badge>
            )
          })}
        </div>
      )}
    </div>
  )
}
