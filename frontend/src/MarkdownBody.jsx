import { Children, useState } from 'react'
import ReactMarkdown from 'react-markdown'
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

const components = {
  pre: CodeBlock,
  a: ({ children, href }) => <a href={href} target="_blank" rel="noopener noreferrer">{children}</a>,
  // Model output must not silently trigger requests to tracking/exfiltration URLs.
  img: ({ src, alt }) => <a href={src} target="_blank" rel="noopener noreferrer">Open image: {alt || 'external image'}</a>,
}

export default function MarkdownBody({ content }) {
  return <ReactMarkdown remarkPlugins={[remarkGfm]} rehypePlugins={[rehypeHighlight]} components={components}>
    {content}
  </ReactMarkdown>
}
