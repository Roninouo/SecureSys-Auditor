export function safeLabel(value?: string | null, fallback = 'Uncategorized') {
  return (value ?? '').replace(/_/g, ' ') || fallback
}
