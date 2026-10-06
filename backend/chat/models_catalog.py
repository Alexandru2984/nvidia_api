"""Catalog of NVIDIA NIM chat models, validated live against the API."""

NVIDIA_MODELS = [
    {
        "id": 'abacusai/dracarys-llama-3.1-70b-instruct',
        "name": 'Dracarys Llama 3.1 70B Instruct',
        "vendor": 'AbacusAI',
        "description": 'AbacusAI fine-tune of Llama 3.1 70B optimized for coding tasks.',
        "context": 128000,
    },
    {
        "id": 'bytedance/seed-oss-36b-instruct',
        "name": 'Seed Oss 36B Instruct',
        "vendor": 'ByteDance',
        "description": 'ByteDance open-source 36B instruct model.',
        "context": 32768,
    },
    {
        "id": 'meta/llama-3.1-70b-instruct',
        "name": 'Llama 3.1 70B Instruct',
        "vendor": 'Meta',
        "description": 'Meta Llama 3.1 70B Instruct.',
        "context": 128000,
    },
    {
        "id": 'meta/llama-3.1-8b-instruct',
        "name": 'Llama 3.1 8B Instruct',
        "vendor": 'Meta',
        "description": 'Meta Llama 3.1 8B Instruct — fast general-purpose.',
        "context": 128000,
    },
    {
        "id": 'meta/llama-3.2-11b-vision-instruct',
        "name": 'Llama 3.2 11B Vision Instruct',
        "vendor": 'Meta',
        "description": 'Meta Llama 3.2 11B Vision Instruct.',
        "context": 128000,
    },
    {
        "id": 'meta/llama-3.2-3b-instruct',
        "name": 'Llama 3.2 3B Instruct',
        "vendor": 'Meta',
        "description": 'Meta Llama 3.2 3B — small efficient model.',
        "context": 128000,
    },
    {
        "id": 'meta/llama-3.2-90b-vision-instruct',
        "name": 'Llama 3.2 90B Vision Instruct',
        "vendor": 'Meta',
        "description": 'Meta Llama 3.2 90B Vision — large multimodal.',
        "context": 128000,
    },
    {
        "id": 'meta/llama-3.3-70b-instruct',
        "name": 'Llama 3.3 70B Instruct',
        "vendor": 'Meta',
        "description": 'Meta Llama 3.3 70B — improved reasoning over 3.1.',
        "context": 128000,
    },
    {
        "id": 'meta/llama-guard-4-12b',
        "name": 'Llama Guard 4 12B',
        "vendor": 'Meta',
        "description": 'Meta Llama Guard 4 — safety classifier.',
        "context": 32768,
    },
    {
        "id": 'mistralai/ministral-14b-instruct-2512',
        "name": 'Ministral 14B Instruct 2512',
        "vendor": 'Mistral AI',
        "description": 'Mistral Ministral 14B — efficient instruct.',
        "context": 32768,
    },
    {
        "id": 'mistralai/mistral-large-3-675b-instruct-2512',
        "name": 'Mistral Large 3 675B Instruct 2512',
        "vendor": 'Mistral AI',
        "description": 'Mistral Large 3 675B — flagship MoE.',
        "context": 131072,
    },
    {
        "id": 'mistralai/mistral-nemotron',
        "name": 'Mistral Nemotron',
        "vendor": 'Mistral AI',
        "description": 'NVIDIA + Mistral collaboration model.',
        "context": 128000,
    },
    {
        "id": 'mistralai/mistral-small-4-119b-2603',
        "name": 'Mistral Small 4 119B 2603',
        "vendor": 'Mistral AI',
        "description": 'Mistral Small 4 119B.',
        "context": 131072,
    },
    {
        "id": 'mistralai/mixtral-8x7b-instruct-v0.1',
        "name": 'Mixtral 8X7B Instruct V0.1',
        "vendor": 'Mistral AI',
        "description": 'Mistral Mixtral 8x7B MoE Instruct.',
        "context": 32768,
    },
    {
        "id": 'nvidia/ising-calibration-1-35b-a3b',
        "name": 'Ising Calibration 1 35B A3B',
        "vendor": 'NVIDIA',
        "description": 'NVIDIA Ising calibration MoE 35B/A3B.',
        "context": 32768,
    },
    {
        "id": 'nvidia/llama-3.1-nemoguard-8b-content-safety',
        "name": 'Llama 3.1 Nemoguard 8B Content Safety',
        "vendor": 'NVIDIA',
        "description": 'NemoGuard content-safety classifier.',
        "context": 128000,
    },
    {
        "id": 'nvidia/llama-3.1-nemoguard-8b-topic-control',
        "name": 'Llama 3.1 Nemoguard 8B Topic Control',
        "vendor": 'NVIDIA',
        "description": 'NemoGuard topic-control classifier.',
        "context": 128000,
    },
    {
        "id": 'nvidia/llama-3.1-nemotron-nano-8b-v1',
        "name": 'Llama 3.1 Nemotron Nano 8B V1',
        "vendor": 'NVIDIA',
        "description": 'Nemotron Nano 8B — efficient assistant.',
        "context": 128000,
    },
    {
        "id": 'nvidia/llama-3.1-nemotron-nano-vl-8b-v1',
        "name": 'Llama 3.1 Nemotron Nano Vl 8B V1',
        "vendor": 'NVIDIA',
        "description": 'Nemotron Nano VL 8B — vision-language.',
        "context": 128000,
    },
    {
        "id": 'nvidia/llama-3.1-nemotron-safety-guard-8b-v3',
        "name": 'Llama 3.1 Nemotron Safety Guard 8B V3',
        "vendor": 'NVIDIA',
        "description": 'Nemotron safety guard v3.',
        "context": 128000,
    },
    {
        "id": 'nvidia/llama-3.3-nemotron-super-49b-v1',
        "name": 'Llama 3.3 Nemotron Super 49B V1',
        "vendor": 'NVIDIA',
        "description": 'Nemotron Super 49B v1 — strong reasoning.',
        "context": 128000,
    },
    {
        "id": 'nvidia/llama-3.3-nemotron-super-49b-v1.5',
        "name": 'Llama 3.3 Nemotron Super 49B V1.5',
        "vendor": 'NVIDIA',
        "description": 'Nemotron Super 49B v1.5.',
        "context": 128000,
    },
    {
        "id": 'nvidia/nemotron-3-content-safety',
        "name": 'Nemotron 3 Content Safety',
        "vendor": 'NVIDIA',
        "description": 'Nemotron 3 content-safety classifier.',
        "context": 128000,
    },
    {
        "id": 'nvidia/nemotron-3-nano-30b-a3b',
        "name": 'Nemotron 3 Nano 30B A3B',
        "vendor": 'NVIDIA',
        "description": 'Nemotron 3 Nano 30B/A3B MoE.',
        "context": 128000,
    },
    {
        "id": 'nvidia/nemotron-3-super-120b-a12b',
        "name": 'Nemotron 3 Super 120B A12B',
        "vendor": 'NVIDIA',
        "description": 'Nemotron 3 Super 120B/A12B MoE.',
        "context": 128000,
    },
    {
        "id": 'nvidia/nemotron-content-safety-reasoning-4b',
        "name": 'Nemotron Content Safety Reasoning 4B',
        "vendor": 'NVIDIA',
        "description": 'Nemotron 4B safety reasoner.',
        "context": 128000,
    },
    {
        "id": 'nvidia/nemotron-mini-4b-instruct',
        "name": 'Nemotron Mini 4B Instruct',
        "vendor": 'NVIDIA',
        "description": 'Nemotron Mini 4B Instruct.',
        "context": 128000,
    },
    {
        "id": 'nvidia/nemotron-nano-12b-v2-vl',
        "name": 'Nemotron Nano 12B V2 Vl',
        "vendor": 'NVIDIA',
        "description": 'Nemotron Nano 12B v2 VL.',
        "context": 128000,
    },
    {
        "id": 'nvidia/nvidia-nemotron-nano-9b-v2',
        "name": 'Nvidia Nemotron Nano 9B V2',
        "vendor": 'NVIDIA',
        "description": 'NVIDIA Nemotron Nano 9B v2.',
        "context": 128000,
    },
    {
        "id": 'nvidia/riva-translate-4b-instruct-v1.1',
        "name": 'Riva Translate 4B Instruct V1.1',
        "vendor": 'NVIDIA',
        "description": 'NVIDIA Riva Translate 4B v1.1.',
        "context": 32768,
    },
    {
        "id": 'openai/gpt-oss-120b',
        "name": 'Gpt Oss 120B',
        "vendor": 'OpenAI',
        "description": 'OpenAI GPT-OSS 120B — open-weight flagship.',
        "context": 128000,
    },
    {
        "id": 'openai/gpt-oss-20b',
        "name": 'Gpt Oss 20B',
        "vendor": 'OpenAI',
        "description": 'OpenAI GPT-OSS 20B — open-weight efficient.',
        "context": 128000,
    },
    {
        "id": 'qwen/qwen3-next-80b-a3b-instruct',
        "name": 'QWEN3 Next 80B A3B Instruct',
        "vendor": 'Alibaba Qwen',
        "description": 'Qwen 3 Next 80B/A3B Instruct.',
        "context": 128000,
    },
    {
        "id": 'qwen/qwen3.5-122b-a10b',
        "name": 'QWEN3.5 122B A10B',
        "vendor": 'Alibaba Qwen',
        "description": 'Qwen 3.5 122B/A10B MoE.',
        "context": 128000,
    },
    {
        "id": 'qwen/qwen3.5-397b-a17b',
        "name": 'QWEN3.5 397B A17B',
        "vendor": 'Alibaba Qwen',
        "description": 'Qwen 3.5 397B/A17B MoE — flagship.',
        "context": 128000,
    },
    {
        "id": 'sarvamai/sarvam-m',
        "name": 'Sarvam M',
        "vendor": 'Sarvam AI',
        "description": 'Sarvam M — Indic-language LLM.',
        "context": 32768,
    },
    {
        "id": 'stepfun-ai/step-3.5-flash',
        "name": 'Step 3.5 Flash',
        "vendor": 'StepFun',
        "description": 'StepFun Step 3.5 Flash.',
        "context": 32768,
    },
    {
        "id": 'stockmark/stockmark-2-100b-instruct',
        "name": 'Stockmark 2 100B Instruct',
        "vendor": 'Stockmark',
        "description": 'Stockmark 2 100B — Japanese-focused.',
        "context": 32768,
    },
    {
        "id": 'upstage/solar-10.7b-instruct',
        "name": 'Solar 10.7B Instruct',
        "vendor": 'Upstage',
        "description": 'Upstage Solar 10.7B Instruct.',
        "context": 4096,
    },
]

DEFAULT_MODEL_ID = "meta/llama-3.1-8b-instruct"
MODEL_IDS = {m["id"] for m in NVIDIA_MODELS}


# Capability metadata is a security boundary, not just UI decoration. Keep this
# conservative: a model is image-capable only after its NVIDIA endpoint/model
# card documents OpenAI-compatible image_url input.
MODEL_IMAGE_CAPABILITIES = {
    'meta/llama-3.2-11b-vision-instruct',
    'meta/llama-3.2-90b-vision-instruct',
    'meta/llama-guard-4-12b',
    'mistralai/ministral-14b-instruct-2512',
    'mistralai/mistral-large-3-675b-instruct-2512',
    'mistralai/mistral-small-4-119b-2603',
    'nvidia/llama-3.1-nemotron-nano-vl-8b-v1',
    'nvidia/nemotron-3-content-safety',
    'nvidia/nemotron-nano-12b-v2-vl',
    'qwen/qwen3.5-122b-a10b',
    'qwen/qwen3.5-397b-a17b',
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
# per provider request. The older Nano VL inline endpoint requires assets above
# 180 KiB, which this application intentionally does not upload to third-party
# object storage.
MODEL_IMAGE_OVERRIDES = {
    'nvidia/llama-3.1-nemotron-nano-vl-8b-v1': {
        'max_images': 1,
        'max_image_bytes': 180 * 1024,
    },
    'nvidia/nemotron-nano-12b-v2-vl': {
        'max_images': 5,
        'image_mime_types': (*DEFAULT_IMAGE_MIME_TYPES, 'image/webp'),
    },
}

SAFETY_MODEL_IDS = {
    'meta/llama-guard-4-12b',
    'nvidia/llama-3.1-nemoguard-8b-content-safety',
    'nvidia/llama-3.1-nemoguard-8b-topic-control',
    'nvidia/llama-3.1-nemotron-safety-guard-8b-v3',
    'nvidia/nemotron-3-content-safety',
    'nvidia/nemotron-content-safety-reasoning-4b',
}
TRANSLATION_MODEL_IDS = {'nvidia/riva-translate-4b-instruct-v1.1'}
CODING_MODEL_IDS = {'abacusai/dracarys-llama-3.1-70b-instruct'}
SPECIALIZED_MODEL_IDS = {
    'nvidia/ising-calibration-1-35b-a3b',
    # NVIDIA labels this older VL endpoint demonstration-only, not production.
    'nvidia/llama-3.1-nemotron-nano-vl-8b-v1',
}


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


MODEL_BY_ID = {model['id']: model for model in NVIDIA_MODELS}

# Keep the legacy `vision` flag while exposing an extensible capability contract.
for _m in NVIDIA_MODELS:
    _m['vision'] = _m['id'] in VISION_MODEL_IDS
    _m['purpose'] = _purpose_for(_m['id'])
    _m['recommended'] = _m['purpose'] in {'assistant', 'coding'}
    _m['capabilities'] = _capabilities_for(_m['id'])


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
IMAGE_GEN_MODEL_IDS = {m['id'] for m in IMAGE_GEN_MODELS}
DEFAULT_IMAGE_GEN_MODEL_ID = 'black-forest-labs/flux.1-schnell'
