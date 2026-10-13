"""Provider-safe generation limits shared by persistence, API, and catalog."""

TEMPERATURE_MIN = 0.0
TEMPERATURE_MAX = 1.0
TEMPERATURE_STEP = 0.1
TEMPERATURE_DEFAULT = 0.7

MAX_TOKENS_MIN = 64
MAX_TOKENS_MAX = 8192
MAX_TOKENS_STEP = 64
MAX_TOKENS_DEFAULT = 1024

# Overrides are conservative NVIDIA-hosted endpoint contracts. The Riva v2 API
# documents 0/512 defaults and a 4096-token output ceiling.
MODEL_GENERATION_OVERRIDES = {
    'nvidia/riva-translate-4b-instruct-v2': {
        'temperature_default': 0.0,
        'max_tokens_default': 512,
        'max_tokens_max': 4096,
    },
}


def model_generation_limits(model_id):
    override = MODEL_GENERATION_OVERRIDES.get(model_id, {})
    return {
        'temperature': {
            'min': TEMPERATURE_MIN,
            'max': TEMPERATURE_MAX,
            'step': TEMPERATURE_STEP,
            'default': override.get('temperature_default', TEMPERATURE_DEFAULT),
        },
        'max_tokens': {
            'min': MAX_TOKENS_MIN,
            'max': override.get('max_tokens_max', MAX_TOKENS_MAX),
            'step': MAX_TOKENS_STEP,
            'default': override.get('max_tokens_default', MAX_TOKENS_DEFAULT),
        },
    }
