import { Children, useState } from 'react'
import ReactMarkdown, { defaultUrlTransform } from 'react-markdown'
import rehypeHighlight from 'rehype-highlight'
import remarkGfm from 'remark-gfm'
import 'highlight.js/styles/github-dark.css'

function textOf(children) {
  return Children.toArray(children).map((child) =>
    typeof child === 'string' || typeof child === 'number' ? child : textOf(child?.props?.children),
  ).join('')
}

function CodeBlock({ children }) {
  const [copied, setCopied] = useState(false)
  async function copy() {
    try {
      await navigator.clipboard.writeText(textOf(children))
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch { setCopied(false) }
  }
  return <div className="code-block">
    <button className="copy-btn" type="button" onClick={copy}>{copied ? 'Copied' : 'Copy code'}</button>
    <pre>{children}</pre>
  </div>
}

const MODEL_LINK_PROTOCOL = /^(https?|mailto):/i

function modelOutputUrl(value) {
  const safe = defaultUrlTransform(value)
  if (!safe) return ''
  const protocol = safe.match(/^[a-z][a-z\d+.-]*:/i)
  return !protocol || MODEL_LINK_PROTOCOL.test(protocol[0]) ? safe : ''
}

const components = {
  pre: CodeBlock,
  a: ({ children, href }) => href
    ? <a href={href} target="_blank" rel="noopener noreferrer" referrerPolicy="no-referrer">{children}</a>
    : <span className="blocked-model-link">{children}</span>,
  // Model output must not silently trigger requests to tracking/exfiltration URLs.
  img: ({ src, alt }) => src
    ? <a href={src} target="_blank" rel="noopener noreferrer" referrerPolicy="no-referrer">Open image: {alt || 'external image'}</a>
    : <span className="blocked-model-link">Blocked image: {alt || 'external image'}</span>,
}

export default function MarkdownBody({ content }) {
  return <ReactMarkdown
    remarkPlugins={[remarkGfm]}
    rehypePlugins={[rehypeHighlight]}
    components={components}
    urlTransform={modelOutputUrl}
  >
    {content}
  </ReactMarkdown>
}
