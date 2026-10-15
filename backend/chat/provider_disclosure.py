"""Minimal, versioned acknowledgement for NVIDIA-bound user content."""

from .models import ProviderDisclosureAcceptance


CURRENT_PROVIDER_DISCLOSURE_VERSION = 1


def provider_disclosure_state(user):
    acceptance = ProviderDisclosureAcceptance.objects.filter(user=user).first()
    accepted = bool(
        acceptance
        and acceptance.version == CURRENT_PROVIDER_DISCLOSURE_VERSION
    )
    return {
        'required_version': CURRENT_PROVIDER_DISCLOSURE_VERSION,
        'accepted': accepted,
        'accepted_at': acceptance.accepted_at.isoformat() if accepted else None,
    }


def has_current_provider_disclosure(user):
    return ProviderDisclosureAcceptance.objects.filter(
        user=user,
        version=CURRENT_PROVIDER_DISCLOSURE_VERSION,
    ).exists()
