# SPDX-License-Identifier: Apache-2.0
"""Ablation switches read from the environment. All off by default."""

import os


def no_verifier() -> bool:
    """Run without the verifier (FB_ABLATE_NO_VERIFIER=1).

    No SP is screened out: every SP the finder records goes straight to PoV
    generation with the finder's own score as its queue priority, whatever that
    score is. The PoV agent gets no verifier output (evidence, notes, PoV
    guidance) -- only what the finder wrote.
    """
    return os.environ.get("FB_ABLATE_NO_VERIFIER", "").lower() in ("1", "true", "yes")
