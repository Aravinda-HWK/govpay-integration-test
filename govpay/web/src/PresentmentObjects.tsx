import type { PresentmentObject } from './api'

// Renders the GovPay+ presentment / payment object array the way the spec
// describes: label, textBox, comboBox and table object types (§2.4.3.2).
export function PresentmentObjects({ objects }: { objects: PresentmentObject[] }) {
  const sorted = [...objects].sort((a, b) => Number(a.seq) - Number(b.seq))
  return (
    <div className="objects">
      {sorted.map((o) => (
        <ObjectField key={`${o.seq}-${o.id}`} obj={o} />
      ))}
    </div>
  )
}

function ObjectField({ obj }: { obj: PresentmentObject }) {
  const type = obj.objType.toLowerCase()
  const value = obj.initialValue == null ? '' : String(obj.initialValue)
  const editable = obj.enabled?.toLowerCase() === 'true'

  if (type === 'table') {
    return <TableField obj={obj} />
  }

  if (type === 'combobox' || type === 'combo') {
    return (
      <div className="field">
        <label>{obj.placeholder}</label>
        <select defaultValue={value} disabled={!editable}>
          {(obj.objData ?? []).map((item) => (
            <option key={item.id} value={item.data}>
              {item.data}
            </option>
          ))}
        </select>
      </div>
    )
  }

  // label and textBox both render as a value; textBox is an input box.
  return (
    <div className="field">
      <label>
        {obj.placeholder}
        {obj.isPaymentAmount && <span className="badge">amount</span>}
        {obj.isPaymentReference && <span className="badge">reference</span>}
      </label>
      {type === 'textbox' ? (
        <input type="text" defaultValue={value} readOnly={!editable} />
      ) : (
        <div className={`label-value${editable ? '' : ' readonly'}`}>{value || '—'}</div>
      )}
    </div>
  )
}

function TableField({ obj }: { obj: PresentmentObject }) {
  const td = obj.tableData
  if (!td) return null
  const cols = td.header.length || obj.cols || 1
  // rowData is a flat array of cells; chunk it into rows of `cols` width.
  const rows: typeof td.rowData[] = []
  for (let i = 0; i < td.rowData.length; i += cols) {
    rows.push(td.rowData.slice(i, i + cols))
  }
  return (
    <div className="field">
      {obj.placeholder && <label>{obj.placeholder}</label>}
      <table className="data-table">
        <thead>
          <tr>
            {td.header.map((h, i) => (
              <th key={i}>{h.value}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, ri) => (
            <tr key={ri}>
              {row.map((cell, ci) => (
                <td key={ci}>{cell.value}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
