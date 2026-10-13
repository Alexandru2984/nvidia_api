"""Documented NVIDIA-hosted chat models, conservatively gated by live probes."""

from .generation import MODEL_GENERATION_OVERRIDES, model_generation_limits

NVIDIA_MODELS = [
    {
        'id': 'nvidia/nemotron-3.5-lightning-30b-a3b',
        'name': 'Nemotron 3.5 Lightning 30B A3B',
        'vendor': 'NVIDIA',
        'description': 'Fast 30B/3B-active MoE for chat, coding, reasoning, and agentic work.',
        'context': 1_048_576,
    },
    {
        'id': 'z-ai/glm-5.3-flash',
        'name': 'GLM 5.3 Flash',
        'vendor': 'Z.ai',
        'description': 'Efficient multimodal reasoning MoE with long context and image understanding.',
        'context': 1_048_576,
    },
    {
        'id': 'nvidia/nemotron-3-super-120b-a12b',
        'name': 'Nemotron 3 Super 120B A12B',
        'vendor': 'NVIDIA',
        'description': 'Long-context MoE for reasoning, planning, instruction following, and coding.',
        'context': 1_048_576,
    },
    {
        'id': 'nvidia/nemotron-3-ultra-550b-a55b',
        'name': 'Nemotron 3 Ultra 550B A55B',
        'vendor': 'NVIDIA',
        'description': 'Large long-context MoE for advanced reasoning, coding, and planning.',
        'context': 1_048_576,
    },
    {
        'id': 'poolside/laguna-xs-2.1',
        'name': 'Laguna XS 2.1',
        'vendor': 'Poolside',
        'description': '33B/3B-active MoE for coding and long-horizon software engineering.',
        'context': 262_144,
    },
    {
        'id': 'openai/gpt-oss-20b',
        'name': 'GPT-OSS 20B',
        'vendor': 'OpenAI',
        'description': 'Efficient open-weight MoE for reasoning, math, and general chat.',
        'context': 128_000,
    },
    {
        'id': 'meta/muse-glimmer-30b',
        'name': 'Muse Glimmer 30B',
        'vendor': 'Meta',
        'description': 'Multimodal reasoning model for text, images, and visual analysis.',
        'context': 131_072,
    },
    {
        'id': 'google/diffusiongemma-26b-a4b-it',
        'name': 'DiffusionGemma 26B A4B IT',
        'vendor': 'Google',
        'description': 'Multimodal diffusion LLM for fast reasoning over text and images.',
        'context': 262_144,
    },
    {
        'id': 'meta/llama-3.2-11b-vision-instruct',
        'name': 'Llama 3.2 11B Vision Instruct',
        'vendor': 'Meta',
        'description': 'Vision-language assistant for image reasoning, captioning, and visual Q&A.',
        'context': 128_000,
    },
    {
        'id': 'nvidia/ising-calibration-1.5-31b',
        'name': 'Ising Calibration 1.5 31B',
        'vendor': 'NVIDIA',
        'description': 'Specialized vision model for quantum-computing calibration plots.',
        'context': 262_144,
    },
    {
        'id': 'nvidia/riva-translate-4b-instruct-v2',
        'name': 'Riva Translate 4B Instruct V2',
        'vendor': 'NVIDIA',
        'description': 'Translation model covering 37 languages, including Romanian.',
        'context': 32_768,
    },
    {
        'id': 'nvidia/llama-3.1-nemotron-safety-guard-8b-v3',
        'name': 'Llama 3.1 Nemotron Safety Guard 8B V3',
        'vendor': 'NVIDIA',
        'description': 'Multilingual safety and moderation classifier for LLM conversations.',
        'context': 128_000,
    },
    {
        'id': 'nvidia/nemotron-3.5-content-safety',
        'name': 'Nemotron 3.5 Content Safety',
        'vendor': 'NVIDIA',
        'description': 'Multilingual, multimodal classifier for unsafe or toxic content.',
        'context': 128_000,
    },
    {
        'id': 'deepseek-ai/deepseek-v4.1-flash',
        'name': 'DeepSeek V4.1 Flash',
        'vendor': 'DeepSeek AI',
        'description': 'Long-context multimodal MoE for reasoning, coding, and agents.',
        'context': 1_048_576,
    },
    {
        'id': 'google/gemma-4-31b-it',
        'name': 'Gemma 4 31B IT',
        'vendor': 'Google',
        'description': 'Multimodal reasoning model for coding, agentic, and visual workflows.',
        'context': 262_144,
    },
    {
        'id': 'meta/llama-3.2-90b-vision-instruct',
        'name': 'Llama 3.2 90B Vision Instruct',
        'vendor': 'Meta',
        'description': 'Large vision-language assistant for detailed image reasoning.',
        'context': 128_000,
    },
    {
        'id': 'meta/llama-guard-4-12b',
        'name': 'Llama Guard 4 12B',
        'vendor': 'Meta',
        'description': 'Multimodal safety classifier for prompts and model responses.',
        'context': 128_000,
    },
    {
        'id': 'moonshotai/kimi-k3',
        'name': 'Kimi K3',
        'vendor': 'Moonshot AI',
        'description': 'Native multimodal MoE for long-horizon coding, reasoning, and visual work.',
        'context': 1_048_576,
    },
    {
        'id': 'nvidia/llama-3.1-nemoguard-8b-content-safety',
        'name': 'Llama 3.1 NemoGuard 8B Content Safety',
        'vendor': 'NVIDIA',
        'description': 'Text safety classifier for prompts and assistant responses.',
        'context': 128_000,
    },
    {
        'id': 'z-ai/glm-5.3',
        'name': 'GLM 5.3',
        'vendor': 'Z.ai',
        'description': 'Large text MoE for deep reasoning, tool use, and long-context chat.',
        'context': 1_048_576,
    },
]

DEFAULT_MODEL_ID = 'nvidia/nemotron-3.5-lightning-30b-a3b'
MODEL_IDS = {model['id'] for model in NVIDIA_MODELS}


# Capability metadata is a security boundary, not just UI decoration. Keep this
# conservative: a model is image-capable only after its NVIDIA endpoint/model
# card documents OpenAI-compatible image_url input.
MODEL_IMAGE_CAPABILITIES = {
    'deepseek-ai/deepseek-v4.1-flash',
    'google/diffusiongemma-26b-a4b-it',
    'google/gemma-4-31b-it',
    'meta/llama-3.2-11b-vision-instruct',
    'meta/llama-3.2-90b-vision-instruct',
    'meta/llama-guard-4-12b',
    'meta/muse-glimmer-30b',
    'moonshotai/kimi-k3',
    'nvidia/ising-calibration-1.5-31b',
    'nvidia/nemotron-3.5-content-safety',
    'z-ai/glm-5.3-flash',
}
VISION_MODEL_IDS = frozenset(MODEL_IMAGE_CAPABILITIES)

DOCUMENT_EXTENSIONS = ('pdf', 'txt', 'md', 'docx')
DEFAULT_IMAGE_MIME_TYPES = ('image/jpeg', 'image/png')
IMAGE_EXTENSIONS_BY_MIME = {
    'image/jpeg': ('jpg', 'jpeg'),
    'image/png': ('png',),
    'image/webp': ('webp',),
}

# Provider-specific constraints. Unknown limits stay conservative: one JPEG/PNG
# per request. Raise a limit only after the hosted contract documents it and an
# inline-data probe succeeds.
MODEL_IMAGE_OVERRIDES = {
    'z-ai/glm-5.3-flash': {
        'max_images': 8,
        'image_mime_types': (*DEFAULT_IMAGE_MIME_TYPES, 'image/webp'),
    },
}

SAFETY_MODEL_IDS = {
    'meta/llama-guard-4-12b',
    'nvidia/llama-3.1-nemoguard-8b-content-safety',
    'nvidia/llama-3.1-nemotron-safety-guard-8b-v3',
    'nvidia/nemotron-3.5-content-safety',
}
TRANSLATION_MODEL_IDS = {'nvidia/riva-translate-4b-instruct-v2'}
CODING_MODEL_IDS = {'poolside/laguna-xs-2.1'}
SPECIALIZED_MODEL_IDS = {'nvidia/ising-calibration-1.5-31b'}


def _purpose_for(model_id):
    if model_id in SAFETY_MODEL_IDS:
        return 'safety'
    if model_id in TRANSLATION_MODEL_IDS:
        return 'translation'
    if model_id in CODING_MODEL_IDS:
        return 'coding'
    if model_id in SPECIALIZED_MODEL_IDS:
        return 'specialized'
    return 'assistant'


def _capabilities_for(model_id):
    image_spec = MODEL_IMAGE_OVERRIDES.get(model_id, {})
    image_mimes = (
        tuple(image_spec.get('image_mime_types', DEFAULT_IMAGE_MIME_TYPES))
        if model_id in VISION_MODEL_IDS else ()
    )
    image_extensions = tuple(
        extension
        for mime in image_mimes
        for extension in IMAGE_EXTENSIONS_BY_MIME[mime]
    )
    return {
        'input_modalities': [
            'text', 'document', *(['image'] if model_id in VISION_MODEL_IDS else []),
        ],
        'attachment_extensions': [*DOCUMENT_EXTENSIONS, *image_extensions],
        'document_extensions': list(DOCUMENT_EXTENSIONS),
        'documents_as_text': True,
        'image_mime_types': list(image_mimes),
        'max_images': image_spec.get('max_images', 1) if image_mimes else 0,
        'max_image_bytes': image_spec.get('max_image_bytes'),
    }


def _best_for(model_id):
    """Conservative guidance derived only from declared app capabilities."""
    purpose = _purpose_for(model_id)
    if purpose == 'safety':
        return 'Safety classification and policy checks'
    if purpose == 'translation':
        return 'Translation workflows'
    if purpose == 'coding':
        return 'Code generation and debugging'
    if purpose == 'specialized':
        return 'Specialized evaluation workflows'
    if model_id in VISION_MODEL_IDS:
        return 'Image and document analysis'
    return 'General chat and document analysis'


_CLASSIFIED_MODEL_IDS = (
    MODEL_IMAGE_CAPABILITIES
    | SAFETY_MODEL_IDS
    | TRANSLATION_MODEL_IDS
    | CODING_MODEL_IDS
    | SPECIALIZED_MODEL_IDS
)
if len(MODEL_IDS) != len(NVIDIA_MODELS):
    raise RuntimeError('Duplicate NVIDIA model ID in catalog.')
if (
    DEFAULT_MODEL_ID not in MODEL_IDS
    or not (_CLASSIFIED_MODEL_IDS | set(MODEL_GENERATION_OVERRIDES)) <= MODEL_IDS
):
    raise RuntimeError('Model capability metadata references an unknown catalog ID.')

MODEL_BY_ID = {model['id']: model for model in NVIDIA_MODELS}

# Keep the legacy `vision` flag while exposing an extensible capability contract.
for _model in NVIDIA_MODELS:
    _model['vision'] = _model['id'] in VISION_MODEL_IDS
    _model['purpose'] = _purpose_for(_model['id'])
    _model['recommended'] = _model['purpose'] in {'assistant', 'coding'}
    _model['best_for'] = _best_for(_model['id'])
    _model['capabilities'] = _capabilities_for(_model['id'])
    _model['generation'] = model_generation_limits(_model['id'])

    _temperature = _model['generation']['temperature']
    _max_tokens = _model['generation']['max_tokens']
    if not (
        _temperature['min'] <= _temperature['default'] <= _temperature['max']
        and _max_tokens['min'] <= _max_tokens['default'] <= _max_tokens['max']
    ):
        raise RuntimeError(f"Invalid generation limits for {_model['id']}.")


def model_capabilities(model_id):
    model = MODEL_BY_ID.get(model_id)
    return model['capabilities'] if model else None


def attachment_capability_issue(model_id, kind, mime_type, size=0):
    """Return a stable error code/message when an attachment is incompatible."""
    capabilities = model_capabilities(model_id)
    if capabilities is None:
        return 'unknown_model', 'The selected model is not in the catalog.'
    if kind == 'document':
        return None
    if kind not in {'image', 'generated_image'}:
        return 'attachment_type_unsupported', 'This attachment type is not supported.'
    if 'image' not in capabilities['input_modalities']:
        return 'images_not_supported', 'The selected model accepts text and documents, but not images.'
    if mime_type not in capabilities['image_mime_types']:
        formats = ', '.join(
            extension.upper()
            for extension in capabilities['attachment_extensions']
            if extension not in DOCUMENT_EXTENSIONS
        )
        return 'image_format_unsupported', f'This model accepts only {formats} images.'
    provider_limit = capabilities['max_image_bytes']
    if provider_limit and size > provider_limit:
        return (
            'image_too_large_for_model',
            f'This model accepts inline images up to {provider_limit // 1024} KB.',
        )
    return None


# Image generation catalog — separate endpoint at NVIDIA_GENAI_BASE/{id}.
# FLUX endpoints only accept these exact dimensions — the API 422s on anything
# else (e.g. 512), even though it looks like a free-form pixel field.
FLUX_ALLOWED_DIMS = [768, 832, 896, 960, 1024, 1088, 1152, 1216, 1280, 1344]

IMAGE_GEN_MODELS = [
    {
        'id': 'black-forest-labs/flux.1-schnell',
        'name': 'FLUX.1 schnell',
        'vendor': 'Black Forest Labs',
        'description': 'Fast 4-step distilled FLUX. Best for quick drafts.',
        'default_steps': 4,
        'max_steps': 8,
        'allowed_dims': FLUX_ALLOWED_DIMS,
    },
    {
        'id': 'black-forest-labs/flux.1-dev',
        'name': 'FLUX.1 dev',
        'vendor': 'Black Forest Labs',
        'description': 'Higher-quality FLUX. Slower but more faithful.',
        'default_steps': 28,
        'max_steps': 50,
        'allowed_dims': FLUX_ALLOWED_DIMS,
    },
]
IMAGE_GEN_MODEL_IDS = {model['id'] for model in IMAGE_GEN_MODELS}
DEFAULT_IMAGE_GEN_MODEL_ID = 'black-forest-labs/flux.1-schnell'
