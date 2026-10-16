"""The oracle must query the private /grading/solves endpoint with the secret
token header, not the public /api/Challenges list (which no longer serves the
answer key to the pentest agent).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import check_live_app  # noqa: E402


def test_build_request_targets_grading_endpoint_with_token():
    req = check_live_app.build_request("http://127.0.0.1:3000", "s3cr3t")

    assert req.full_url == "http://127.0.0.1:3000/grading/solves"
    # urllib normalizes header names to Title-Case
    assert req.get_header("X-grading-token") == "s3cr3t"


def test_build_request_strips_trailing_slash_on_base_url():
    req = check_live_app.build_request("http://127.0.0.1:3000/", "t")

    assert req.full_url == "http://127.0.0.1:3000/grading/solves"
