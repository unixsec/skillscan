import { useId, useRef } from 'react'
import { useI18n } from '../i18n/I18nContext'

interface FileFieldProps {
  label: string
  accept?: string
  file: File | null
  onSelect: (file: File | null) => void
  disabled?: boolean
}

// A styled upload control: a clearly-visible button that opens the native file
// dialog via a hidden input, plus the selected filename. Replaces raw
// `<input type="file">`, whose default "选择文件" button rendered dark-on-dark
// in this theme and gave no confirmation a file was actually picked - it read
// as unresponsive even though the click worked.
export function FileField({ label, accept, file, onSelect, disabled }: FileFieldProps) {
  const { t } = useI18n()
  const inputRef = useRef<HTMLInputElement>(null)
  const inputId = useId()

  return (
    <div className="file-field">
      <span className="file-field-label">{label}</span>
      <div className="file-field-row">
        <input
          ref={inputRef}
          id={inputId}
          type="file"
          accept={accept}
          disabled={disabled}
          className="file-field-input"
          onChange={(e) => onSelect(e.target.files?.[0] ?? null)}
        />
        <button
          type="button"
          disabled={disabled}
          onClick={() => inputRef.current?.click()}
        >
          {t('common.chooseFile')}
        </button>
        <span className={file ? 'file-field-name' : 'file-field-name is-empty'}>
          {file ? file.name : t('common.noFileSelected')}
        </span>
      </div>
    </div>
  )
}
