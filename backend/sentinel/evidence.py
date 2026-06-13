from __future__ import annotations

from .models import EvidenceBundle, PatchProposal, ValidationResult, sha256_text, stable_json


def patch_digest(patch: PatchProposal) -> str:
    """Hash the complete security-relevant patch payload."""
    return sha256_text(
        stable_json(
            {
                "patch_id": patch.patch_id,
                "task_id": patch.task_id,
                "iteration": patch.iteration,
                "files": [file.model_dump(mode="json") for file in patch.files],
                "unified_diff": patch.unified_diff,
                "risk": patch.risk,
                "engineer_confidence": patch.engineer_confidence,
            }
        )
    )


def validation_digest(validation: ValidationResult) -> str:
    return sha256_text(stable_json(validation.model_dump(mode="json")))


def build_evidence_bundle(
    *,
    session_id: str,
    repository_path: str,
    patch: PatchProposal,
    validation: ValidationResult,
) -> EvidenceBundle:
    metadata = validation.sandbox_metadata
    bundle = EvidenceBundle(
        session_id=session_id,
        patch_id=patch.patch_id,
        patch_sha256=patch_digest(patch),
        repository_path=repository_path,
        validation_id=validation.validation_id,
        validation_sha256=validation_digest(validation),
        sandbox_engine=metadata.engine if metadata else "unknown",
        sandbox_isolation=metadata.isolation_level if metadata else "process",
        workspace_sha256=metadata.workspace_sha256 if metadata else "",
    )
    
    # Generate cryptographic signature
    # In production, this would use an asymmetric key (RSA/ECDSA) from Azure Key Vault
    secret_key = b"sentinel-dev-secret-key-00000000"
    payload = stable_json(bundle.model_dump(mode="json", exclude={"cryptographic_signature", "evidence_id", "created_at"}))
    signature = hmac.new(secret_key, payload.encode("utf-8"), hashlib.sha256).hexdigest()
    bundle.cryptographic_signature = f"hmac-sha256:{signature}"
    
    return bundle
