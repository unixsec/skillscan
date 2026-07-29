import { useMemo, useState } from 'react'
import { useI18n } from '../i18n/I18nContext'

export interface FilterField<T> {
  key: string
  label: string
  // Value extracted from a row for this field (stringified for comparison).
  // Rows may carry SEVERAL values for one field - a scan legitimately has N
  // submitters once identical content is deduplicated onto one scan_job - so
  // this returns a list and a row matches when ANY of its values is the chosen
  // one. Returning the first value only would hide a scan from the very person
  // who submitted it whenever someone else got there first.
  value: (row: T) => string | string[]
  // Optional human label for a distinct value (e.g. enum -> translated text).
  renderOption?: (value: string) => string
}

function valuesOf<T>(field: FilterField<T>, row: T): string[] {
  const raw = field.value(row)
  return Array.isArray(raw) ? raw : [raw]
}

interface FilterState {
  [key: string]: string
}

// Client-side dropdown filtering for an already-loaded table. Derives the
// distinct set of values per field from the current rows, renders a "全部 +
// each value" <select> per field, and returns the filtered rows. Kept
// client-side deliberately: these list endpoints already return the full set
// the page renders, so filtering in the browser needs no new API surface and
// stays instant.
export function useTableFilter<T>(rows: T[], fields: FilterField<T>[]) {
  const [selected, setSelected] = useState<FilterState>({})

  const options = useMemo(() => {
    const byField: Record<string, string[]> = {}
    for (const field of fields) {
      const seen = new Set<string>()
      for (const row of rows) {
        for (const v of valuesOf(field, row)) {
          if (v !== '' && v !== 'undefined' && v !== 'null') seen.add(v)
        }
      }
      byField[field.key] = [...seen].sort()
    }
    return byField
  }, [rows, fields])

  const filtered = useMemo(
    () =>
      rows.filter((row) =>
        fields.every((field) => {
          const chosen = selected[field.key]
          return !chosen || valuesOf(field, row).includes(chosen)
        }),
      ),
    [rows, fields, selected],
  )

  return { filtered, options, selected, setSelected }
}

interface TableFilterBarProps<T> {
  fields: FilterField<T>[]
  options: Record<string, string[]>
  selected: FilterState
  onChange: (next: FilterState) => void
}

export function TableFilterBar<T>({ fields, options, selected, onChange }: TableFilterBarProps<T>) {
  const { t } = useI18n()
  const anyOptions = fields.some((f) => (options[f.key]?.length ?? 0) > 0)
  if (!anyOptions) return null
  return (
    <div className="table-filter-bar">
      {fields.map((field) => {
        const values = options[field.key] ?? []
        if (values.length === 0) return null
        return (
          <label key={field.key} className="table-filter">
            {field.label}
            <select
              value={selected[field.key] ?? ''}
              onChange={(e) => onChange({ ...selected, [field.key]: e.target.value })}
            >
              <option value="">{t('filter.all')}</option>
              {values.map((v) => (
                <option key={v} value={v}>
                  {field.renderOption ? field.renderOption(v) : v}
                </option>
              ))}
            </select>
          </label>
        )
      })}
    </div>
  )
}
