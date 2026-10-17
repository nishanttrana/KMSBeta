// Options for a role or status selector: the tenant's own values, plus the
// current one when the tenant doesn't define it, so a selector never shows
// another value in its place.
export function selectOptions(values: readonly string[], current?: string) {
  const list = current && !values.includes(current) ? [...values, current] : values;
  return list.map((value) => (
    <option key={value} value={value}>{values.includes(value) ? value : `${value} (not defined)`}</option>
  ));
}
