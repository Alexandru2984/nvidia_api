export const DOCUMENT_EXTENSIONS = ['pdf', 'txt', 'md', 'docx']

const COMPATIBILITY_REASON_LABELS = [
  ['document_text', 'document has no extracted text'],
  ['image_input', 'image input is not supported'],
  ['image_format', 'image format is not supported'],
  ['image_size', 'image exceeds this model\'s size limit'],
  ['image_limit', 'per-request image limit is exceeded'],
  ['unsupported_type', 'file type is not supported'],
]

const FALLBACK_IMAGE_EXTENSIONS = ['jpg', 'jpeg', 'png']

export function capabilitiesFor(model) {
  if (model?.capabilities) return model.capabilities
  const imageExtensions = model?.vision ? FALLBACK_IMAGE_EXTENSIONS : []
  return {
    input_modalities: ['text', 'document', ...(model?.vision ? ['image'] : [])],
    attachment_extensions: [...DOCUMENT_EXTENSIONS, ...imageExtensions],
    document_extensions: DOCUMENT_EXTENSIONS,
    documents_as_text: true,
    image_mime_types: model?.vision ? ['image/jpeg', 'image/png'] : [],
    max_images: model?.vision ? 1 : 0,
    max_image_bytes: null,
  }
}

function baseIncompatibilityReason(attachment, capabilities) {
  if (attachment.kind === 'document') {
    return attachment.has_text === false ? 'document_text' : null
  }
  if (!['image', 'generated_image'].includes(attachment.kind)) return 'unsupported_type'
  if (!capabilities.input_modalities.includes('image')) return 'image_input'
  if (!capabilities.image_mime_types.includes(attachment.mime_type)) return 'image_format'
  if (capabilities.max_image_bytes && attachment.size > capabilities.max_image_bytes) {
    return 'image_size'
  }
  return null
}

export function attachmentIsCompatible(attachment, capabilities) {
  return baseIncompatibilityReason(attachment, capabilities) === null
}

export function incompatibleAttachmentsForModel(attachments, model) {
  return attachmentCompatibilityForModel(attachments, model).incompatible
}

export function attachmentCompatibilityForModel(attachments, model) {
  const capabilities = capabilitiesFor(model)
  let remainingImages = Number.isInteger(capabilities.max_images)
    ? Math.max(0, capabilities.max_images)
    : 0
  const incompatible = []
  const reasonCounts = {}

  for (const attachment of attachments) {
    let reason = baseIncompatibilityReason(attachment, capabilities)
    if (!reason && ['image', 'generated_image'].includes(attachment.kind)) {
      if (remainingImages < 1) reason = 'image_limit'
      else remainingImages -= 1
    }
    if (!reason) continue
    incompatible.push(attachment)
    reasonCounts[reason] = (reasonCounts[reason] || 0) + 1
  }

  return {
    compatible: incompatible.length === 0,
    incompatible,
    reason_counts: reasonCounts,
    total: attachments.length,
  }
}

export function attachmentCompatibilityReasonSummary(compatibility) {
  return COMPATIBILITY_REASON_LABELS
    .filter(([reason]) => compatibility?.reason_counts?.[reason])
    .map(([, label]) => label)
    .join('; ')
}
