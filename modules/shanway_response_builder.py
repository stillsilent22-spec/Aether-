"""Deterministic 6-field Shanway response rendering."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class ShanwayStructuredResponse:
    ergebnis: str
    quellenkonsistenz: str
    quellen_symmetrie: float
    symmetrie_score: float
    symmetrie_label: str
    vault_abgleich: str
    vault_detail: str
    unsicherheiten: list[str]
    endbewertung: str
    keine_datenlage: bool
    quellen_widerspruechlich: bool

    def render(self) -> str:
        unsicherheiten = "keine" if not self.unsicherheiten else "; ".join(self.unsicherheiten)
        return (
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "[1] ERGEBNIS\n"
            f"{self.ergebnis}\n\n"
            "[2] QUELLENKONSISTENZ\n"
            f"{self.quellenkonsistenz} | Symmetrie-Score: {self.quellen_symmetrie:.2f}\n\n"
            "[3] STRUKTURSYMMETRIE\n"
            f"{self.symmetrie_score:.3f} -> {self.symmetrie_label}\n\n"
            "[4] VAULT-ABGLEICH\n"
            f"{self.vault_abgleich}: {self.vault_detail}\n\n"
            "[5] UNSICHERHEITEN\n"
            f"{unsicherheiten}\n\n"
            "[6] ENDBEWERTUNG\n"
            f"{self.endbewertung}\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "ergebnis": str(self.ergebnis),
            "quellenkonsistenz": str(self.quellenkonsistenz),
            "quellen_symmetrie": float(self.quellen_symmetrie),
            "symmetrie_score": float(self.symmetrie_score),
            "symmetrie_label": str(self.symmetrie_label),
            "vault_abgleich": str(self.vault_abgleich),
            "vault_detail": str(self.vault_detail),
            "unsicherheiten": list(self.unsicherheiten),
            "endbewertung": str(self.endbewertung),
            "keine_datenlage": bool(self.keine_datenlage),
            "quellen_widerspruechlich": bool(self.quellen_widerspruechlich),
        }


class ShanwayResponseBuilder:
    """Builds deterministic structured Shanway responses."""

    def build(
        self,
        assessment: Any,
        interface_result: Any,
        raw_answer: str = "",
    ) -> ShanwayStructuredResponse:
        web_context = dict(getattr(interface_result, "web_context", {}) or {})
        consistency = str(web_context.get("consistency", "") or "")
        ok = bool(web_context.get("ok", False))
        raw = str(raw_answer or "").strip()
        keine_datenlage = False
        quellen_widerspruechlich = False
        unsicherheiten: list[str] = []

        if str(getattr(assessment, "classification", "") or "") == "inactive":
            ergebnis = "Shanway inaktiv"
        elif not ok and not raw:
            ergebnis = "Keine ausreichende Datenlage"
            keine_datenlage = True
            reason = str(web_context.get("reason", "") or "")
            if reason:
                unsicherheiten.append(reason)
        elif consistency == "low":
            ergebnis = "Quellen widerspruechlich - keine sichere Aussage moeglich"
            quellen_widerspruechlich = True
            unsicherheiten.append("Quellen widerspruechlich")
        else:
            ergebnis = raw or str(getattr(assessment, "message", "") or "Keine ausreichende Datenlage")

        noether = float(getattr(assessment, "noether_symmetry", 0.0) or 0.0)
        if noether >= 0.80:
            symmetrie_label = "stabil"
        elif noether >= 0.60:
            symmetrie_label = "fragil"
            unsicherheiten.append("Struktursymmetrie nur fragil")
        else:
            symmetrie_label = "Strukturbruch"
            unsicherheiten.append("Struktursymmetrie zu niedrig")

        quellenkonsistenz = "keine Webdaten"
        if ok:
            mapping = {"high": "hoch", "medium": "mittel", "low": "niedrig"}
            quellenkonsistenz = mapping.get(consistency, "mittel")
        elif str(web_context.get("reason", "") or "") == "skipped_due_to_load":
            quellenkonsistenz = "keine Webdaten"

        vault_abgleich = str(
            web_context.get(
                "vault_abgleich",
                getattr(interface_result, "library_context", {}).get("vault_abgleich", "unbekannt")
                if hasattr(interface_result, "library_context")
                else "unbekannt",
            )
            or "unbekannt"
        )
        vault_detail = str(
            web_context.get(
                "vault_detail",
                getattr(interface_result, "library_context", {}).get("detail", "Kein stabiler Vault-Abgleich")
                if hasattr(interface_result, "library_context")
                else "Kein stabiler Vault-Abgleich",
            )
            or "Kein stabiler Vault-Abgleich"
        )
        if vault_abgleich == "widerspruechlich":
            unsicherheiten.append("Vault-Wissen widerspricht")

        if keine_datenlage or quellen_widerspruechlich or symmetrie_label == "Strukturbruch":
            endbewertung = "unsicher"
        elif unsicherheiten or symmetrie_label == "fragil":
            endbewertung = "vorsichtig"
        else:
            endbewertung = "stabil"

        return ShanwayStructuredResponse(
            ergebnis=ergebnis,
            quellenkonsistenz=quellenkonsistenz,
            quellen_symmetrie=float(web_context.get("source_symmetry", 0.0) or 0.0),
            symmetrie_score=noether,
            symmetrie_label=symmetrie_label,
            vault_abgleich=vault_abgleich,
            vault_detail=vault_detail,
            unsicherheiten=list(dict.fromkeys(str(item) for item in unsicherheiten if str(item).strip())),
            endbewertung=endbewertung,
            keine_datenlage=keine_datenlage,
            quellen_widerspruechlich=quellen_widerspruechlich,
        )

    @staticmethod
    def render(response: ShanwayStructuredResponse) -> str:
        return response.render()
