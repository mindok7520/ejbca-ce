export function short(value) {
  return value ? `${value.slice(0, 8)}...` : '-';
}

export function formatTs(value) {
  return value ? new Date(value * 1000).toLocaleString() : '-';
}

export function formatDetails(value) {
  if (!value || value === '{}') return '-';
  return value.length > 80 ? `${value.slice(0, 80)}...` : value;
}
