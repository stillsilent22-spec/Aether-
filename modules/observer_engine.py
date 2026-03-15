def observer_engine(O):
    """Erzeugt Metadaten für ein gegebenes Objekt O im neuen Modulkontext."""
    metadata = {
        "length": O.get("length", None),
        "byte_sum": sum(O.get("bytes", b"")),
        "source": O.get("source", "aether"),
        "timestamp": O.get("timestamp"),
    }
    return {"O": O, "metadata": metadata}

def observer_learning_rate(t: int) -> float:
    """Deterministische Lernratenfunktion: lr = 1 / (1 + t)"""
    return 1.0 / (1 + int(t))

def observer_time_decay(value: float, t: int, half_life: int) -> float:
    """Exponentieller Zerfall: value * (0.5 ** (t / half_life))"""
    return float(value) * (0.5 ** (float(t) / float(half_life)))
"""Beobachter-Pipeline fuer Kameraanker, Metriken und Delta-Logs."""

from __future__ import annotations
import math

            "version": 1,
    if p_a <= 0 or p_b <= 0 or p_a >= 1 or p_b >= 1:
        return 0.0
    return math.log2(p_a / p_b)

            "symmetry_history": symmetry_history,
    if b == 0:
        return 0.0
    return a / b

            "residual_history": residual_history,
    if t < 0:
        t = 0
    return 1.0 / (1.0 + float(t))

            "delta_i_obs_history": delta_history,
    if half_life <= 0:
        return value
    return value * (0.5 ** (float(t) / float(half_life)))
            "recursive_depth_history": depth_history,
            "learned_insights": learned_insights,
            "current_insight": str(current_insight),
            "public_anchor_count": int(len(public_anchor_hashes)),
            "public_anchor_hashes": public_anchor_hashes,
            "last_global_learn_delta": round(float(imported_count * 0.07), 12) if imported_count > 0 else float(last_global_learn_delta),
        }
        self.save_learning_state(session_context, updated)
        return updated

    def merge_public_anchor_bundle(self, session_context, bundle_payload: dict[str, object] | None) -> dict[str, object]:
        """Integriert importierte oeffentliche Anker lokal in den Lernzustand."""
        payload = dict(bundle_payload or {})
        public_anchors = [
            dict(item)
            for item in list(payload.get("public_anchors", []) or [])
            if isinstance(item, dict)
        ]
        trusted_anchor_count = int(payload.get("trusted_anchor_count", len(public_anchors)) or len(public_anchors))
        pending_quorum_count = int(payload.get("candidate_anchor_count", 0) or 0)
        quorum_validated_count = int(payload.get("quorum_validated_count", 0) or 0)
        admin_trusted_count = int(payload.get("admin_trusted_count", 0) or 0)
        previous_state = self.load_learning_state(session_context)
        previous_count = int(len(list(previous_state.get("public_anchor_hashes", []) or [])))
        updated = self.update_learning_state(session_context, reflection_payload={}, imported_public_anchors=public_anchors)
        symmetry_values: list[float] = []
        delta_values: list[float] = []
        for item in public_anchors:
            metrics = dict(item.get("public_metrics", {}) or {})
            symmetry = float(metrics.get("symmetry", 0.0) or 0.0)
            delta_i_obs = float(metrics.get("delta_i_obs_percent", 0.0) or 0.0)
            if symmetry > 0.0:
                symmetry_values.append(symmetry)
            if delta_i_obs > 0.0:
                delta_values.append(delta_i_obs)
        symmetry_gain = round(float(self._rolling_mean(symmetry_values) * 100.0), 12) if symmetry_values else 0.0
        i_obs_gain = round(float(self._rolling_mean(delta_values)), 12) if delta_values else 0.0
        current_count = int(updated.get("public_anchor_count", 0) or 0)
        imported_count = max(0, current_count - previous_count)
        current_insight = str(updated.get("current_insight", "") or "")
        if imported_count > 0 and quorum_validated_count > 0:
            current_insight = (
                f"Anker von 3 Peers validiert -> globales Lernen: +{symmetry_gain:.2f}% Symmetrie-Delta, "
                f"I_obs +{i_obs_gain:.2f}%."
            )
        elif imported_count > 0 and admin_trusted_count > 0:
            current_insight = (
                f"Admin-Anker direkt vertrauenswuerdig -> globales Lernen: +{symmetry_gain:.2f}% Symmetrie-Delta, "
                f"I_obs +{i_obs_gain:.2f}%."
            )
        elif pending_quorum_count > 0 and imported_count <= 0:
            current_insight = (
                f"Quorum offen: {pending_quorum_count} Anker warten noch auf unabhaengige Validierungen, "
                "bevor sie in M_t einfliessen."
            )
        updated["current_insight"] = str(current_insight)
        updated["trusted_public_anchor_count"] = int(trusted_anchor_count)
        updated["pending_public_anchor_count"] = int(pending_quorum_count)
        self.save_learning_state(session_context, updated)
        return {
            "imported_anchor_count": imported_count,
            "public_anchor_count": current_count,
            "trusted_anchor_count": int(trusted_anchor_count),
            "pending_quorum_count": int(pending_quorum_count),
            "quorum_validated_count": int(quorum_validated_count),
            "admin_trusted_count": int(admin_trusted_count),
            "last_global_learn_delta": float(updated.get("last_global_learn_delta", 0.0) or 0.0),
            "symmetry_gain_percent": float(symmetry_gain),
            "i_obs_gain_percent": float(i_obs_gain),
            "current_insight": str(current_insight),
        }

    @staticmethod
    def _clamp(value: float, low: float, high: float) -> float:
        """Begrenzt Werte robust auf ein Intervall."""
        return float(max(low, min(high, value)))

    def _extract_anchors(self, frame_rgb: np.ndarray) -> list[AnchorPoint]:
        """Extrahiert bis zu 14 hochvariante Pixelregionen als Anker."""
        gray = cv2.cvtColor(np.asarray(frame_rgb, dtype=np.uint8), cv2.COLOR_RGB2GRAY)
        gray_f = gray.astype(np.float32)
        mean = cv2.GaussianBlur(gray_f, (0, 0), 2.0)
        sq_mean = cv2.GaussianBlur(gray_f * gray_f, (0, 0), 2.0)
        local_var = np.maximum(0.0, sq_mean - (mean * mean))

        kernel = np.ones((11, 11), dtype=np.uint8)
        maxima = local_var == cv2.dilate(local_var, kernel)
        coords = np.argwhere(maxima)
        if coords.size == 0:
            return []

        values = local_var[maxima]
        order = np.argsort(values)[::-1]
        min_distance = max(16.0, min(gray.shape[0], gray.shape[1]) * 0.12)

        anchors: list[AnchorPoint] = []
        scale = float(np.max(values)) if float(np.max(values)) > 1e-9 else 1.0
        height, width = gray.shape[:2]
        for index in order:
            y_pos, x_pos = coords[index]
            if values[index] <= 1e-9:
                continue
            candidate_x = float(x_pos) / float(max(1, width - 1))
            candidate_y = float(y_pos) / float(max(1, height - 1))
            if any(
                math.hypot((candidate_x - item.x) * width, (candidate_y - item.y) * height) < min_distance
                for item in anchors
            ):
                continue
            anchors.append(
                AnchorPoint(
                    x=candidate_x,
                    y=candidate_y,
                    strength=self._clamp(float(values[index]) / scale, 0.0, 1.0),
                )
            )
            if len(anchors) >= self.max_anchors:
                break
        return anchors

    def predict_ghost_anchors(
        self,
        prior_cells: Sequence[dict[str, float | int]],
    ) -> list[AnchorPoint]:
        """Leitet geisterhafte Vorhersageanker aus den globalen Prior-Haeufigkeiten ab."""
        ghosts: list[AnchorPoint] = []
        if not prior_cells:
            return ghosts

        max_count = max(float(cell.get("count", 1.0)) for cell in prior_cells)
        for cell in prior_cells[: self.max_anchors]:
            ghosts.append(
                AnchorPoint(
                    x=self._clamp(float(cell.get("x_norm", 0.5)), 0.0, 1.0),
                    y=self._clamp(float(cell.get("y_norm", 0.5)), 0.0, 1.0),
                    strength=self._clamp(float(cell.get("count", 0.0)) / max(1.0, max_count), 0.15, 1.0),
                    predicted=True,
                )
            )
        return ghosts

    def _prior_accuracy(
        self,
        predicted: Sequence[AnchorPoint],
        actual: Sequence[AnchorPoint],
        tolerance: float = 0.09,
    ) -> float:
        """Misst, wie viele Geisteranker von realen Ankern bestaetigt werden."""
        if not predicted:
            return 0.0
        hits = 0
        for guess in predicted:
            if any(math.hypot(guess.x - anchor.x, guess.y - anchor.y) <= tolerance for anchor in actual):
                hits += 1
        return float(hits / max(1, len(predicted)))

    def _fractal_dimension(self, anchors: Sequence[AnchorPoint]) -> float:
        """Schaetzt die Beauty-Dimension D per Box-Counting im Bereich (1, 2)."""
        if len(anchors) < 2:
            return 1.0

        points = np.array([[anchor.x, anchor.y] for anchor in anchors], dtype=np.float64)
        scales = [2, 4, 8, 16]
        counts: list[float] = []
        inv_scales: list[float] = []
        for scale in scales:
            bins = np.floor(points * scale).astype(np.int32)
            bins = np.clip(bins, 0, scale - 1)
            occupied = {tuple(item) for item in bins.tolist()}
            if occupied:
                counts.append(float(len(occupied)))
                inv_scales.append(float(scale))
        if len(counts) < 2:
            return 1.0

        slope, _ = np.polyfit(np.log(inv_scales), np.log(counts), 1)
        return self._clamp(float(slope), 1.0, 2.0)

    def _coherence(self, anchors: Sequence[AnchorPoint], entropy_now: float) -> float:
        """Leitet C(t) aus Entropiedrift und Ankerbewegung her."""
        if not self._previous_anchors:
            return 0.64

        movements: list[float] = []
        remaining = list(self._previous_anchors)
        for anchor in anchors:
            if not remaining:
                movements.append(1.0)
                continue
            distances = [math.hypot(anchor.x - prev.x, anchor.y - prev.y) for prev in remaining]
            index = int(np.argmin(distances))
            distance = distances[index]
            previous = remaining.pop(index)
            strength_gap = abs(anchor.strength - previous.strength)
            movements.append(self._clamp((distance / 0.25) + strength_gap, 0.0, 1.5))

        entropy_gap = 0.0
        if self._previous_entropy is not None:
            entropy_gap = abs(entropy_now - self._previous_entropy) / 8.0
        instability = (0.65 * (sum(movements) / max(1, len(movements)))) + (0.35 * entropy_gap)
        return self._clamp(1.0 - instability, 0.0, 1.0)

    def _camera_center_metrics(self, frame_rgb: np.ndarray) -> tuple[float, float]:
        """Berechnet Zentrumsleuchtdichte und horizontales Massenzentrum."""
        gray = cv2.cvtColor(np.asarray(frame_rgb, dtype=np.uint8), cv2.COLOR_RGB2GRAY)
        height, width = gray.shape[:2]
        half_h = max(1, height // 10)
        half_w = max(1, width // 10)
        center = gray[(height // 2) - half_h : (height // 2) + half_h, (width // 2) - half_w : (width // 2) + half_w]
        center_lum = float(np.mean(center)) if center.size else float(np.mean(gray))
        weights = gray.astype(np.float64)
        weight_sum = float(np.sum(weights))
        if weight_sum <= 1e-9:
            center_mass_x = 0.5
        else:
            x_coords = np.linspace(0.0, 1.0, width, dtype=np.float64)
            center_mass_x = float(np.sum(weights.sum(axis=0) * x_coords) / weight_sum)
        return center_lum, center_mass_x

    def _local_entropy_scores(
        self,
        frame_rgb: np.ndarray,
        anchors: Sequence[AnchorPoint],
        radius: int = 14,
    ) -> list[float]:
        """Berechnet Shannon-H ueber gleitende Fenster um jeden Anchor."""
        if not anchors:
            return []
        gray = cv2.cvtColor(np.asarray(frame_rgb, dtype=np.uint8), cv2.COLOR_RGB2GRAY)
        height, width = gray.shape[:2]
        scores: list[float] = []
        for anchor in anchors:
            x_pos = int(round(float(anchor.x) * float(max(1, width - 1))))
            y_pos = int(round(float(anchor.y) * float(max(1, height - 1))))
            x0 = max(0, x_pos - radius)
            y0 = max(0, y_pos - radius)
            x1 = min(width, x_pos + radius + 1)
            y1 = min(height, y_pos + radius + 1)
            patch = gray[y0:y1, x0:x1]
            local_h = _entropy(patch.flatten())
            scores.append(self._clamp(local_h / 8.0, 0.0, 1.0))
        return scores

    def _interference_from_paths(self, entropy_score: float, benford_score: float) -> tuple[float, str]:
        """Leitet konstruktive oder destruktive Interferenz aus zwei Analysepfaden ab."""
        entropy_signal = float(entropy_score) - 0.5
        benford_signal = float(benford_score) - 0.5
        same_direction = (entropy_signal * benford_signal) > 0.0
        if same_direction and min(abs(entropy_signal), abs(benford_signal)) >= 0.15:
            value = self._clamp(min(abs(entropy_signal), abs(benford_signal)), 0.0, 0.5)
            return float(value), "constructive"
        if (entropy_signal * benford_signal) < 0.0 and abs(float(entropy_score) - float(benford_score)) >= 0.15:
            value = -self._clamp(abs(float(entropy_score) - float(benford_score)), 0.0, 1.0)
            return float(value), "destructive"
        return 0.0, "neutral"

    def apply_interference_to_anchors(
        self,
        anchors: Sequence[AnchorPoint],
        entropy_scores: Sequence[float],
        benford_profile: dict[str, object] | None,
        tau: float,
    ) -> tuple[list[AnchorPoint], dict[str, object]]:
        """Fuehrt Entropie- und Benford-Pfad zu einem additiven Interferenzsignal zusammen."""
        if not anchors:
            return [], {
                "benford_score": 0.5,
                "informative": False,
                "mean_interference": 0.0,
                "constructive_count": 0,
                "destructive_count": 0,
                "constructive_ratio": 0.0,
                "destructive_ratio": 0.0,
                "benford_profile": dict(benford_profile or {}),
            }

        profile = dict(benford_profile or {})
        informative = bool(profile.get("informative", False))
        benford_score = float(profile.get("conformity_score", 50.0) or 50.0) / 100.0
        if not informative:
            benford_score = 0.5

        enriched: list[AnchorPoint] = []
        constructive_count = 0
        destructive_count = 0
        interference_values: list[float] = []
        fallback_scores = list(entropy_scores) or [0.5 for _ in anchors]
        if len(fallback_scores) < len(anchors):
            fallback_scores.extend([fallback_scores[-1]] * (len(anchors) - len(fallback_scores)))

        for index, anchor in enumerate(anchors):
            entropy_score = self._clamp(float(fallback_scores[index]), 0.0, 1.0)
            interference, label = self._interference_from_paths(entropy_score, benford_score)
            confidence = self._clamp(
                float(anchor.strength)
                + (0.22 * max(0.0, interference))
                - (0.26 * max(0.0, -interference)),
                0.0,
                1.0,
            )
            if label == "constructive":
                constructive_count += 1
            elif label == "destructive":
                destructive_count += 1
            interference_values.append(float(interference))
            enriched.append(
                AnchorPoint(
                    x=float(anchor.x),
                    y=float(anchor.y),
                    strength=float(anchor.strength),
                    predicted=bool(anchor.predicted),
                    z=float(anchor.strength),
                    tau=float(tau),
                    confidence=float(confidence),
                    interference=float(interference),
                    interference_label=label,
                )
            )

        mean_interference = float(np.mean(interference_values)) if interference_values else 0.0
        return enriched, {
            "benford_score": float(benford_score),
            "informative": bool(informative),
            "mean_interference": mean_interference,
            "constructive_count": int(constructive_count),
            "destructive_count": int(destructive_count),
            "constructive_ratio": float(constructive_count / max(1, len(enriched))),
            "destructive_ratio": float(destructive_count / max(1, len(enriched))),
            "benford_profile": profile,
        }

    def encode_delta_ops(
        self,
        previous: Sequence[AnchorPoint],
        current: Sequence[AnchorPoint],
        tau: float,
    ) -> list[dict[str, float | str]]:
        """Kodiert Ankerveraenderungen als add/remove/move-Deltas."""
        operations: list[dict[str, float | str]] = []
        current_unused = list(current)

        for old_anchor in previous:
            if not current_unused:
                operations.append(
                    {
                        "op": "remove",
                        "x": round(old_anchor.x * 15.0, 4),
                        "y": round(old_anchor.y * 15.0, 4),
                        "z": round(old_anchor.strength * 15.0, 4),
                        "tau": round(float(tau), 3),
                        "strength": round(float(old_anchor.strength), 5),
                    }
                )
                continue

            distances = [math.hypot(old_anchor.x - item.x, old_anchor.y - item.y) for item in current_unused]
            index = int(np.argmin(distances))
            nearest = current_unused[index]
            if distances[index] <= 0.08:
                current_unused.pop(index)
                if distances[index] > 0.015 or abs(nearest.strength - old_anchor.strength) > 0.08:
                    operations.append(
                        {
                            "op": "move",
                            "x": round(nearest.x * 15.0, 4),
                            "y": round(nearest.y * 15.0, 4),
                            "z": round(nearest.strength * 15.0, 4),
                            "tau": round(float(tau), 3),
                            "strength": round(float(nearest.strength), 5),
                        }
                    )
            else:
                operations.append(
                    {
                        "op": "remove",
                        "x": round(old_anchor.x * 15.0, 4),
                        "y": round(old_anchor.y * 15.0, 4),
                        "z": round(old_anchor.strength * 15.0, 4),
                        "tau": round(float(tau), 3),
                        "strength": round(float(old_anchor.strength), 5),
                    }
                )

        for anchor in current_unused:
            operations.append(
                {
                    "op": "add",
                    "x": round(anchor.x * 15.0, 4),
                    "y": round(anchor.y * 15.0, 4),
                    "z": round(anchor.strength * 15.0, 4),
                    "tau": round(float(tau), 3),
                    "strength": round(float(anchor.strength), 5),
                }
            )
        return operations

    def event_benford_profile(
        self,
        operations: Sequence[dict[str, float | str]],
    ) -> dict[str, float | bool | dict[str, int] | dict[str, float]]:
        """Misst Benford-Naehe auf variablen Event-Groessen der Anchor-Deltas."""

        def leading_digit(value: float) -> str:
            magnitude = abs(float(value))
            if magnitude <= 1e-12:
                return ""
            while magnitude < 1.0:
                magnitude *= 10.0
            while magnitude >= 10.0:
                magnitude /= 10.0
            return str(int(magnitude))

        counts = {str(index): 0 for index in range(1, 10)}
        sample_count = 0
        for entry in operations:
            for key in ("x", "y", "z", "tau", "strength"):
                raw_value = entry.get(key)
                try:
                    digit = leading_digit(float(raw_value))
                except (TypeError, ValueError):
                    continue
                if digit in counts:
                    counts[digit] += 1
                    sample_count += 1

        expected = {
            str(index): float(math.log10(1.0 + (1.0 / float(index))))
            for index in range(1, 10)
        }
        if sample_count <= 0:
            return {
                "sample_count": 0,
                "informative": False,
                "leading_digit_counts": counts,
                "observed": {digit: 0.0 for digit in counts},
                "expected": expected,
                "mad": 0.0,
                "conformity_score": 0.0,
            }

        observed = {
            digit: float(count) / float(sample_count)
            for digit, count in counts.items()
        }
        mad = float(
            sum(abs(observed[digit] - expected[digit]) for digit in counts) / float(len(counts))
        )
        informative = sample_count >= 24 and len([digit for digit, count in counts.items() if count > 0]) >= 4
        conformity_score = float(max(0.0, min(100.0, 100.0 * (1.0 - (mad / 0.12)))))
        return {
            "sample_count": int(sample_count),
            "informative": bool(informative),
            "leading_digit_counts": counts,
            "observed": observed,
            "expected": expected,
            "mad": mad,
            "conformity_score": conformity_score,
        }

    def process_frame(
        self,
        frame_rgb: np.ndarray,
        prior_cells: Sequence[dict[str, float | int]],
        phi: float = 0.0,
        h_obs: float = 0.0,
    ) -> ObserverSnapshot:
        """Verarbeitet einen Kamera-Frame zu Ankern, Delta-Log und Live-Metriken."""
        rgb = np.asarray(frame_rgb, dtype=np.uint8)
        gray = cv2.cvtColor(rgb, cv2.COLOR_RGB2GRAY)
        ht = _entropy(gray.flatten())
        if self._initial_entropy is None:
            self._initial_entropy = ht

        raw_anchors = self._extract_anchors(rgb)
        delta_ops = self.encode_delta_ops(self._previous_anchors, raw_anchors, tau=float(len(raw_anchors)))
        benford_profile = self.event_benford_profile(delta_ops)
        entropy_scores = self._local_entropy_scores(rgb, raw_anchors)
        anchors, interference_profile = self.apply_interference_to_anchors(
            raw_anchors,
            entropy_scores,
            benford_profile,
            tau=float(len(raw_anchors)),
        )
        ghost_anchors = self.predict_ghost_anchors(prior_cells)
        prior_accuracy = self._prior_accuracy(ghost_anchors, anchors)
        coherence = self._coherence(anchors, ht)
        beauty_d = self._fractal_dimension(list(anchors) + [ghost for ghost in ghost_anchors[:4]])
        center_lum, center_mass_x = self._camera_center_metrics(rgb)

        freq = 110.0 + (coherence * 440.0)
        detune = (1.0 - (beauty_d / 1.5)) * 1200.0
        metrics = ObserverMetrics(
            h0=float(self._initial_entropy or ht),
            ht=float(ht),
            coherence=float(coherence),
            beauty_d=float(beauty_d),
            phi=float(phi),
            freq=float(freq),
            detune=float(detune),
            prior_accuracy=float(prior_accuracy),
            anchors=len(anchors),
            h_obs=float(h_obs),
            center_lum=float(center_lum),
            center_mass_x=float(center_mass_x),
            interference_score=float(interference_profile.get("mean_interference", 0.0) or 0.0),
            constructive_ratio=float(interference_profile.get("constructive_ratio", 0.0) or 0.0),
            destructive_ratio=float(interference_profile.get("destructive_ratio", 0.0) or 0.0),
        )

        self._previous_anchors = list(anchors)
        self._previous_entropy = float(ht)
        return ObserverSnapshot(
            frame_rgb=rgb,
            anchors=anchors,
            ghost_anchors=ghost_anchors,
            metrics=metrics,
            delta_ops=delta_ops,
            interference_profile=interference_profile,
        )

    def fingerprint_anchors(
        self,
        fingerprint: AetherFingerprint,
        limit: int = 14,
    ) -> list[AnchorPoint]:
        """Leitet Dateianker aus dem Fingerprint fuer Delta-Logs und Vault-Analyse ab."""
        anchors: list[AnchorPoint] = []
        entropy_values = list(fingerprint.entropy_blocks[:256])
        if not entropy_values:
            return anchors

        max_entropy = max(1e-9, max(entropy_values))
        if fingerprint.anomaly_coordinates:
            for x_pos, y_pos in fingerprint.anomaly_coordinates[:limit]:
                index = int(y_pos * 16 + x_pos)
                strength = float(entropy_values[index]) / max_entropy if index < len(entropy_values) else 0.5
                anchors.append(
                    AnchorPoint(
                        x=float(x_pos) / 15.0,
                        y=float(y_pos) / 15.0,
                        strength=self._clamp(strength, 0.0, 1.0),
                        z=self._clamp(strength, 0.0, 1.0),
                        tau=float(index),
                        confidence=self._clamp(strength, 0.0, 1.0),
                    )
                )
            return anchors[:limit]

        top_indices = np.argsort(np.array(entropy_values, dtype=np.float64))[::-1][:limit]
        for index in top_indices.tolist():
            x_pos = index % 16
            y_pos = index // 16
            anchors.append(
                AnchorPoint(
                    x=float(x_pos) / 15.0,
                    y=float(y_pos) / 15.0,
                    strength=self._clamp(float(entropy_values[index]) / max_entropy, 0.0, 1.0),
                    z=self._clamp(float(entropy_values[index]) / max_entropy, 0.0, 1.0),
                    tau=float(index),
                    confidence=self._clamp(float(entropy_values[index]) / max_entropy, 0.0, 1.0),
                )
            )
        return anchors

    def enrich_fingerprint_anchors(
        self,
        fingerprint: AetherFingerprint,
        anchors: Sequence[AnchorPoint],
        delta_ops: Sequence[dict[str, float | str]],
    ) -> tuple[list[AnchorPoint], dict[str, object]]:
        """Fuehrt den Dual-Path-Interferenzlayer auch fuer Dateifingerprint-Anker aus."""
        entropy_values = list(getattr(fingerprint, "entropy_blocks", []) or [])
        if not anchors:
            return [], {
                "benford_score": 0.5,
                "informative": False,
                "mean_interference": 0.0,
                "constructive_count": 0,
                "destructive_count": 0,
                "constructive_ratio": 0.0,
                "destructive_ratio": 0.0,
                "benford_profile": self.event_benford_profile(delta_ops),
            }
        if not entropy_values:
            entropy_scores = [0.5 for _ in anchors]
        else:
            max_entropy = max(1e-9, max(entropy_values))
            entropy_scores = []
            for anchor in anchors:
                x_cell = int(self._clamp(round(float(anchor.x) * 15.0), 0, 15))
                y_cell = int(self._clamp(round(float(anchor.y) * 15.0), 0, 15))
                index = (y_cell * 16) + x_cell
                if 0 <= index < len(entropy_values):
                    entropy_scores.append(self._clamp(float(entropy_values[index]) / max_entropy, 0.0, 1.0))
                else:
                    entropy_scores.append(0.5)
        benford_profile = self.event_benford_profile(delta_ops)
        return self.apply_interference_to_anchors(
            anchors=anchors,
            entropy_scores=entropy_scores,
            benford_profile=benford_profile,
            tau=float(len(anchors)),
        )

    def _render_text_preview(self, lines: Sequence[str], width: int = 960, height: int = 540) -> np.ndarray:
        frame = np.zeros((height, width, 3), dtype=np.uint8)
        y_pos = 40
        for line in list(lines)[:14]:
            cv2.putText(
                frame,
                str(line)[:96],
                (24, y_pos),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.75,
                (220, 235, 255),
                1,
                cv2.LINE_AA,
            )
            y_pos += 32
        return frame

    def _synthetic_render_preview(
        self,
        file_path: str,
        fingerprint: AetherFingerprint | None = None,
    ) -> np.ndarray:
        path = Path(str(file_path))
        profile = dict(getattr(fingerprint, "file_profile", {}) or {})
        category = str(profile.get("category", "binary") or "binary")
        summary = dict(profile.get("summary", {}) or {})

        if category == "image":
            image = cv2.imread(str(path), cv2.IMREAD_COLOR)
            if image is not None:
                return cv2.cvtColor(image, cv2.COLOR_BGR2RGB)

        if category == "video":
            capture = cv2.VideoCapture(str(path))
            ok, frame = capture.read()
            capture.release()
            if ok and frame is not None:
                return cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)

        if category == "audio":
            samples = bytes(getattr(fingerprint, "delta", b"")[:4096]) if fingerprint is not None else b""
            canvas = np.zeros((540, 960, 3), dtype=np.uint8)
            if samples:
                values = np.frombuffer(samples, dtype=np.uint8).astype(np.float32)
                if values.size > 0:
                    values = cv2.resize(values.reshape(1, -1), (900, 1), interpolation=cv2.INTER_AREA).flatten()
                    center = 270
                    for index, value in enumerate(values[:900]):
                        amplitude = int((float(value) / 255.0) * 220.0)
                        x_pos = index + 30
                        cv2.line(canvas, (x_pos, center - amplitude), (x_pos, center + amplitude), (90, 220, 255), 1)
            cv2.putText(canvas, f"AUDIO {path.name}", (24, 40), cv2.FONT_HERSHEY_SIMPLEX, 0.9, (240, 240, 240), 2, cv2.LINE_AA)
            return canvas

        if category == "font":
            return self._render_text_preview(
                [
                    f"FONT PREVIEW: {path.name}",
                    "Sphinx of black quartz, judge my vow.",
                    "0123456789",
                    json.dumps(summary, ensure_ascii=True)[:96],
                ]
            )

        if category in {"document", "code", "data", "archive"}:
            lines = [
                f"{category.upper()} PREVIEW: {path.name}",
                f"MIME: {profile.get('mime_type', 'application/octet-stream')}",
                f"SUBTYPE: {profile.get('subtype', 'opaque')}",
            ]
            for key, value in list(summary.items())[:10]:
                lines.append(f"{key}: {value}")
            return self._render_text_preview(lines)

        return self._render_text_preview(
            [
                f"BINARY PREVIEW: {path.name}",
                f"SIZE: {int(getattr(fingerprint, 'file_size', 0) or 0)} bytes",
                f"H_lambda: {float(getattr(fingerprint, 'h_lambda', 0.0) or 0.0):.3f}",
                f"Symmetry: {float(getattr(fingerprint, 'symmetry_score', 0.0) or 0.0):.2f}",
            ]
        )

    def _capture_scoped_frame(self, region: dict[str, int] | None = None) -> np.ndarray | None:
        if mss is None:
            if pyautogui is None:
                return None
            try:
                screenshot = pyautogui.screenshot(
                    region=(
                        int(region["left"]),
                        int(region["top"]),
                        int(region["width"]),
                        int(region["height"]),
                    )
                ) if region else pyautogui.screenshot()
                return np.asarray(screenshot, dtype=np.uint8)
            except Exception:
                return None
        try:
            with mss.mss() as sct:
                monitor = dict(region or sct.monitors[1])
                frame = np.array(sct.grab(monitor))
            if frame.ndim == 3 and frame.shape[2] >= 3:
                return frame[:, :, :3][:, :, ::-1]
            return frame
        except Exception:
            if pyautogui is None:
                return None
            try:
                screenshot = pyautogui.screenshot()
                return np.asarray(screenshot, dtype=np.uint8)
            except Exception:
                return None

    def _process_snapshot(self) -> dict[str, object]:
        if psutil is None:
            return {"available": False, "missing_dependencies": ["psutil"]}
        process = psutil.Process()
        try:
            cpu_percent = float(process.cpu_percent(interval=0.05))
        except Exception:
            cpu_percent = 0.0
        try:
            memory_info = process.memory_info()
            rss = int(getattr(memory_info, "rss", 0) or 0)
            vms = int(getattr(memory_info, "vms", 0) or 0)
        except Exception:
            rss = 0
            vms = 0
        try:
            io_info = process.io_counters()
            read_bytes = int(getattr(io_info, "read_bytes", 0) or 0)
            write_bytes = int(getattr(io_info, "write_bytes", 0) or 0)
        except Exception:
            read_bytes = 0
            write_bytes = 0
        try:
            open_files = len(process.open_files())
        except Exception:
            open_files = 0
        try:
            connections = len(process.net_connections(kind="all"))
        except Exception:
            connections = 0
        return {
            "available": True,
            "pid": int(process.pid),
            "name": str(process.name()),
            "cpu_percent": float(cpu_percent),
            "rss": int(rss),
            "vms": int(vms),
            "threads": int(process.num_threads()),
            "open_files": int(open_files),
            "network_connections": int(connections),
            "io_read_bytes": int(read_bytes),
            "io_write_bytes": int(write_bytes),
        }

    def observe_render_and_processes(
        self,
        file_path: str,
        timeout: int = 10,
        fingerprint: AetherFingerprint | None = None,
        scoped_region: dict[str, int] | None = None,
        scoped_screen_payload: dict[str, object] | None = None,
    ) -> dict[str, object]:
        """Beobachtet gerenderten Zustand und Prozessresiduum fail-closed ohne externes Oeffnen."""
        start_time = time.perf_counter()
        process_before = self._process_snapshot()
        frame_rgb = self._capture_scoped_frame(region=scoped_region)
        screen_mode = "scoped_capture"
        if frame_rgb is None:
            frame_rgb = self._synthetic_render_preview(file_path=file_path, fingerprint=fingerprint)
            screen_mode = "synthetic_preview"
        gray = cv2.cvtColor(np.asarray(frame_rgb, dtype=np.uint8), cv2.COLOR_RGB2GRAY)
        visual_entropy = _entropy(gray.flatten())
        visual_hash = hashlib.sha256(np.asarray(frame_rgb, dtype=np.uint8).tobytes()).hexdigest()
        visual_metrics = {
            "mode": str(screen_mode),
            "width": int(frame_rgb.shape[1]),
            "height": int(frame_rgb.shape[0]),
            "visual_entropy": round(float(visual_entropy), 12),
            "visual_hash": str(visual_hash),
            "screen_payload": dict(scoped_screen_payload or {}),
            "pyautogui_available": bool(pyautogui is not None),
            "mss_available": bool(mss is not None),
        }
        process_after = self._process_snapshot()
        process_residuum = {
            "before": process_before,
            "after": process_after,
            "timeout": int(timeout),
            "elapsed_ms": round(float((time.perf_counter() - start_time) * 1000.0), 3),
        }
        visual_residual = {
            "hash": str(visual_hash),
            "entropy": round(float(visual_entropy), 12),
            "frame_shape": [int(value) for value in list(frame_rgb.shape)],
        }
        process_hash = hashlib.sha256(json.dumps(process_residuum, ensure_ascii=True, sort_keys=True).encode("utf-8")).hexdigest()
        return {
            "screen_vision_mode": str(screen_mode),
            "visual_state": visual_metrics,
            "process_state": process_after,
            "visual_residual": visual_residual,
            "process_residuum": process_residuum,
            "visual_residual_hash": str(visual_hash),
            "process_residuum_hash": str(process_hash),
            "O_t": {
                "visual_entropy": round(float(visual_entropy), 12),
                "cpu_percent": float(dict(process_after or {}).get("cpu_percent", 0.0) or 0.0),
                "threads": int(dict(process_after or {}).get("threads", 0) or 0),
            },
            "M_t": {
                "file_category": str(dict(getattr(fingerprint, "file_profile", {}) or {}).get("category", "binary")),
                "observer_state": str(getattr(fingerprint, "observer_state", "OFFEN") if fingerprint is not None else "OFFEN"),
                "screen_mode": str(screen_mode),
            },
            "R_t": {
                "visual_residual_hash": str(visual_hash),
                "process_residuum_hash": str(process_hash),
            },
        }

    def prior_cells_from_anchors(self, anchors: Iterable[AnchorPoint]) -> list[tuple[int, int]]:
        """Projiziert Anker auf ein persistentes 20x20-Prior-Raster."""
        cells: list[tuple[int, int]] = []
        for anchor in anchors:
            x_cell = int(self._clamp(round(anchor.x * 19.0), 0, 19))
            y_cell = int(self._clamp(round(anchor.y * 19.0), 0, 19))
            cells.append((x_cell, y_cell))
        return cells
