export const DOCUMENT_EXTENSIONS = ['pdf', 'txt', 'md', 'docx']

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

export function attachmentIsCompatible(attachment, capabilities) {
  if (attachment.kind === 'document') return attachment.has_text !== false
  if (!['image', 'generated_image'].includes(attachment.kind)) return false
  return capabilities.input_modalities.includes('image')
    && capabilities.image_mime_types.includes(attachment.mime_type)
    && (!capabilities.max_image_bytes || attachment.size <= capabilities.max_image_bytes)
}

export function incompatibleAttachmentsForModel(attachments, model) {
  const capabilities = capabilitiesFor(model)
  let remainingImages = Number.isInteger(capabilities.max_images)
    ? Math.max(0, capabilities.max_images)
    : 0

  return attachments.filter((attachment) => {
    if (!attachmentIsCompatible(attachment, capabilities)) return true
    if (!['image', 'generated_image'].includes(attachment.kind)) return false
    if (remainingImages < 1) return true
    remainingImages -= 1
    return false
  })
}

export function attachmentCompatibilityForModel(attachments, model) {
  const incompatible = incompatibleAttachmentsForModel(attachments, model)
  return {
    compatible: incompatible.length === 0,
    incompatible,
    total: attachments.length,
  }
}
