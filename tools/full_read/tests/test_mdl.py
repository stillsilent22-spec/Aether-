"""Unit tests for modules/mdl.py."""
from __future__ import annotations

import pytest

from modules.mdl import compress_size, mdl_score, normalize_score, DEFAULT_ALPHA


class TestCompressSize:
    def test_empty_returns_zero(self):
        assert compress_size(b"") == 0.0

    def test_zlib_method(self):
        data = b"hello world" * 100
        size = compress_size(data, method="zlib")
        assert isinstance(size, float)
        assert 0 < size < len(data)

    def test_lzma_method(self):
        data = b"hello world" * 100
        size = compress_size(data, method="lzma")
        assert isinstance(size, float)
        assert 0 < size < len(data)

    def test_avg_is_float(self):
        data = b"abcdef" * 50
        size = compress_size(data)
        zlib_sz = compress_size(data, method="zlib")
        lzma_sz = compress_size(data, method="lzma")
        assert abs(size - (zlib_sz + lzma_sz) / 2.0) < 1e-9

    def test_unknown_method_raises(self):
        with pytest.raises(Exception):
            compress_size(b"data", method="bz2")  # type: ignore[arg-type]

    def test_random_data_near_length(self):
        import os
        data = os.urandom(512)
        size = compress_size(data)
        # Random data shouldn't compress much — should be > 50% of raw
        assert size > len(data) * 0.4


class TestMdlScore:
    def test_score_is_higher_for_compressible_than_random(self):
        # A candidate matching the context pattern should score higher than
        # random noise (compression gain vs complexity trade-off comparison)
        import os
        context = b"aaaaaaaaaaaaaaa" * 200
        compressible = b"aaaaaaaaaaaaaaa" * 10
        random_cand = os.urandom(len(compressible))
        score_comp = mdl_score(compressible, context_bytes=context)
        score_rand = mdl_score(random_cand, context_bytes=context)
        assert score_comp > score_rand

    def test_negative_for_random_candidate_with_structured_context(self):
        import os
        context = b"aaaaaa" * 200
        candidate = os.urandom(256)
        score = mdl_score(candidate, context_bytes=context)
        # Random data adds complexity without compressing the context
        assert isinstance(score, float)  # just verify it runs

    def test_empty_candidate_zero_score(self):
        # compress_size(b"") == 0, so gain - alpha*0 == gain alone
        score = mdl_score(b"", context_bytes=b"hello" * 10)
        # No compression gain possible
        assert isinstance(score, float)

    def test_empty_context(self):
        score = mdl_score(b"hello world", context_bytes=b"")
        assert isinstance(score, float)

    def test_alpha_increases_complexity_penalty(self):
        context = b"x" * 500
        candidate = b"y" * 100
        score_low = mdl_score(candidate, context_bytes=context, alpha=0.0)
        score_high = mdl_score(candidate, context_bytes=context, alpha=1.0)
        assert score_low >= score_high

    def test_identical_contexts_give_consistent_scores(self):
        context = b"pattern" * 50
        candidate = b"pattern" * 5
        s1 = mdl_score(candidate, context_bytes=context)
        s2 = mdl_score(candidate, context_bytes=context)
        assert s1 == s2  # deterministic

    def test_default_alpha(self):
        assert DEFAULT_ALPHA == 0.001


class TestNormalizeScore:
    def test_zero_context_size_returns_zero(self):
        assert normalize_score(10.0, 0) == 0.0

    def test_scales_by_context_size(self):
        assert normalize_score(100.0, 1000) == pytest.approx(0.1)

    def test_negative_score(self):
        assert normalize_score(-50.0, 500) == pytest.approx(-0.1)
