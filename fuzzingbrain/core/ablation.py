# SPDX-License-Identifier: Apache-2.0
"""Ablation switches read from the environment. All off by default."""

import os


def no_fuzzers() -> bool:
    """Run without the Global and SP fuzzers (FB_ABLATE_NO_FUZZERS=1).

    No FuzzerManager is created, so no fuzzer, crash monitor or fuzzer seeds
    (delta / FP / direction seeds only feed the fuzzers); every PoV comes from
    a PoV agent's create_pov. With nothing left to raise new SPs once the
    finder is done, the pipeline agents exit when their work is drained and
    the task ends when every worker has finished.
    """
    return os.environ.get("FB_ABLATE_NO_FUZZERS", "").lower() in ("1", "true", "yes")
