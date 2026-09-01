export function formatModelName(name) {
  if (!name) return ''
  if (Array.isArray(name)) return name.map(formatModelName).join(', ')
  if (name.includes('llama3.2:3b')) return name.replace('llama3.2:3b', 'Llama 3.2: 3B')
  if (name.includes('qwen2.5:3b')) return name.replace('qwen2.5:3b', 'Qwen 2.5: 3B')
  return name.charAt(0).toUpperCase() + name.slice(1)
}
