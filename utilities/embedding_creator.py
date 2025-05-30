import json
import pickle
from pathlib import Path
from typing import Any

from numpy import ndarray
from sentence_transformers import SentenceTransformer
from tqdm import tqdm

from commons.attack_patterns import NormalizedAttackPattern
from commons.attack_relationships import Relationship
from commons.cve_items import CVEItem
from commons.instruction_bundle import IntrusionSet
from commons.logger import get_logger
from config import Config

logger = get_logger(__name__)


class EntityEmbedder:
    def __init__(
        self,
        model_name: str = "sentence-transformers/all-MiniLM-L6-v2",
    ) -> None:
        self.encoder = SentenceTransformer(model_name)
        self.model = SentenceTransformer(model_name)

    def _embed_text(self, text: str) -> ndarray:
        return self.model.encode(text, convert_to_numpy=True)

    # -------------------------------
    #   intrusion_bundle
    # -------------------------------
    def _embed_intrusion_set(self, iset: IntrusionSet) -> dict[str, Any]:
        def extract_fields_for_intrusion_set(obj: IntrusionSet) -> dict:
            return {
                "id": obj.id,
                "name": obj.name,
                "description": obj.description or "",
                "aliases": " ".join(obj.aliases),
                "domains": " ".join(obj.x_mitre_domains),
                "external_references": " ".join(
                    f"""{ref.source_name} {ref.external_id or ""}
                    {ref.url or ""} {ref.description or ""}""".strip()
                    for ref in obj.external_references
                ),
                "created": obj.created.isoformat() if obj.created else "",
                "modified": obj.modified.isoformat() if obj.modified else "",
                "revoked": str(obj.revoked),
                "created_by_ref": obj.created_by_ref,
                "object_marking_refs": " ".join(obj.object_marking_refs),
                "x_mitre_deprecated": str(obj.x_mitre_deprecated),
                "x_mitre_version": obj.x_mitre_version or "",
                "x_mitre_contributors": " ".join(obj.x_mitre_contributors or []),
                "x_mitre_attack_spec_version": obj.x_mitre_attack_spec_version or "",
                "x_mitre_modified_by_ref": obj.x_mitre_modified_by_ref or "",
            }

        extracted = extract_fields_for_intrusion_set(iset)
        return {
            "id": extracted["id"],
            "embeddings": {
                k: self._embed_text(v) for k, v in extracted.items() if k != "id"
            },
            "metadata": extracted,
        }

    def embed_intrusion_sets_from_directory(
        self,
        input_dir: str,
        output_file: str,
    ) -> None:
        input_path = Path(input_dir)
        output_path = Path(output_file)
        results = []

        try:
            for file_path in tqdm(input_path.glob("*.json")):
                with file_path.open("r", encoding="utf-8") as f:
                    data = json.load(f)
                    try:
                        intrusion_set = IntrusionSet(**data)
                        embedded = self._embed_intrusion_set(intrusion_set)
                        results.append(embedded)
                    except Exception as item_error:
                        msg = f"""Skipping invalid bundle in
                        {file_path.name}: {item_error}"""
                        logger.exception(msg)

            output_path.parent.mkdir(parents=True, exist_ok=True)
            with output_path.open("wb") as f:
                pickle.dump(results, f)

            msg = f"Embedded {len(results)} IntrusionSet saved to: {output_file}"
            logger.info(msg)
        except Exception as e:
            msg = f"embed_intrusion_sets_from_directory error: {e}"
            logger.exception(msg)

    # -------------------------------
    #   cve_item
    # -------------------------------
    def _embed_cve_item(self, cve_item: CVEItem) -> dict[str, Any]:
        def extract_fields_for_cve(item: CVEItem) -> dict:
            extracted = {
                "id": item.cve.cve_data_meta.id,
                "description": " ".join(
                    d.value for d in item.cve.description.description_data
                ),
                "references": " ".join(
                    r.url for r in item.cve.references.reference_data
                ),
                "problem_types": " ".join(
                    d.value or ""
                    for p in item.cve.problem_type.problemtype_data
                    for d in p.description
                ),
                "assigner": item.cve.cve_data_meta.assigner,
                "published_date": item.published_date,
            }

            # Add structured CVSSv3 fields
            if item.impact.base_metric_v3:
                cvss = item.impact.base_metric_v3.cvss_v3
                extracted.update({
                    "cvss_vector": cvss.vector_string,
                    "cvss_base_score": str(cvss.base_score),
                    "cvss_base_severity": cvss.base_severity,
                    "attack_vector": cvss.attack_vector,
                    "attack_complexity": cvss.attack_complexity,
                    "privileges_required": cvss.privileges_required,
                    "user_interaction": cvss.user_interaction,
                    "scope": cvss.scope,
                    "confidentiality_impact": cvss.confidentiality_impact,
                    "integrity_impact": cvss.integrity_impact,
                    "availability_impact": cvss.availability_impact,
                })

            return extracted

        extracted = extract_fields_for_cve(cve_item)
        return {
            "id": extracted["id"],
            "embeddings": {
                k: self._embed_text(v) for k, v in extracted.items() if k != "id"
            },
            "metadata": extracted,
        }

    def embed_cve_items_from_directory(
        self,
        input_dir: str,
        output_file: str,
    ) -> None:
        input_path = Path(input_dir)
        output_path = Path(output_file)
        results = []

        try:
            i = 100
            for file_path in tqdm(input_path.glob("*.json")):
                if i <= 0:
                    break
                i -= 1
                with file_path.open("r", encoding="utf-8") as f:
                    data = json.load(f)
                    items = data if isinstance(data, list) else [data]
                    for item_data in items:
                        try:
                            cve_item = CVEItem(**item_data)
                            embedded = self._embed_cve_item(cve_item)
                            results.append(embedded)
                        except Exception as item_error:  # noqa: PERF203
                            msg = f"""Skipping invalid item in
                            {file_path.name}: {item_error}"""
                            logger.exception(msg)

            output_path.parent.mkdir(parents=True, exist_ok=True)
            with output_path.open("wb") as f:
                pickle.dump(results, f)

            msg = f" Embedded {len(results)} CVEItems saved to: {output_file}"
            logger.info(msg)
        except Exception as e:
            msg = f"embed_cve_items_from_directory error: {e}"
            logger.exception(msg)

    # -------------------------------
    #   attack_pattern
    # -------------------------------
    def _embed_attack_pattern(self, ap: NormalizedAttackPattern) -> dict[str, Any]:
        def extract_fields_for_ap(ap: NormalizedAttackPattern) -> dict:
            extracted = {
                "id": ap.id,
                "name": ap.name,
                "description": ap.description or "",
                "external_id": ap.external_id or "",
                "source_url": ap.source_url or "",
                "deprecated": str(ap.deprecated),
                "version": ap.version or "",
                "created": ap.created.isoformat() if ap.created else "",
                "modified": ap.modified.isoformat() if ap.modified else "",
            }

            if ap.kill_chain:
                extracted["kill_chain_name"] = ap.kill_chain.name
                extracted["kill_chain_phase"] = ap.kill_chain.phase

            if ap.detectable_by_defense:
                extracted["defense_status"] = ap.detectable_by_defense.status or ""
                extracted["defense_explanation"] = (
                    ap.detectable_by_defense.explanation or ""
                )

            if ap.adversary_difficulty:
                extracted["adversary_status"] = ap.adversary_difficulty.status or ""
                extracted["adversary_explanation"] = (
                    ap.adversary_difficulty.explanation or ""
                )

            return extracted

        extracted = extract_fields_for_ap(ap)
        return {
            "id": extracted["id"],
            "embeddings": {
                k: self._embed_text(v) for k, v in extracted.items() if k != "id"
            },
            "metadata": extracted,
        }

    def embed_attack_patterns_from_directory(
        self,
        input_dir: str,
        output_file: str,
    ) -> None:
        input_path = Path(input_dir)
        output_path = Path(output_file)
        results = []

        try:
            i = 100
            for file_path in tqdm(input_path.glob("*.json")):
                if i <= 0:
                    break
                i -= 1
                with file_path.open("r", encoding="utf-8") as f:
                    data = json.load(f)
                    items = data if isinstance(data, list) else [data]
                    for item_data in items:
                        try:
                            ap = NormalizedAttackPattern(**item_data)
                            embedded = self._embed_attack_pattern(ap)
                            results.append(embedded)
                        except Exception as item_error:  # noqa: PERF203
                            msg = f"""Skipping invalid attack pattern in
                            {file_path.name}: {item_error}"""
                            logger.exception(msg)

            output_path.parent.mkdir(parents=True, exist_ok=True)
            with output_path.open("wb") as f:
                pickle.dump(results, f)

            msg = f"Embedded {len(results)} attack patterns saved to: {output_file}"
            logger.info(msg)
        except Exception as e:
            msg = f"embed_attack_patterns_from_directory error: {e}"
            logger.exception(msg)

    # -----------
    # Attack_relationship
    # ------------
    def _embed_relationship(self, rel: Relationship) -> dict[str, Any]:
        def extract_fields_for_relationship(rel: Relationship) -> dict:
            return {
                "id": rel.id,
                "type": rel.type,
                "relationship_type": rel.relationship_type,
                "source_ref": rel.source_ref,
                "target_ref": rel.target_ref,
                "description": rel.description or "",
                "created_by_ref": rel.created_by_ref or "",
                "created": rel.created.isoformat() if rel.created else "",
                "modified": rel.modified.isoformat() if rel.modified else "",
                "object_marking_refs": " ".join(rel.object_marking_refs)
                if rel.object_marking_refs
                else "",
                "external_references": " ".join(
                    f"""{ref.source_name} {ref.external_id or ""}
                    {ref.url or ""} {ref.description or ""}"""
                    for ref in rel.external_references or []
                ),
            }

        extracted = extract_fields_for_relationship(rel)
        return {
            "id": extracted["id"],
            "embeddings": {
                k: self._embed_text(v) for k, v in extracted.items() if k != "id"
            },
            "metadata": extracted,
        }

    def embed_relationships_from_directory(
        self,
        input_dir: str,
        output_file: str,
    ) -> None:
        input_path = Path(input_dir)
        output_path = Path(output_file)
        results = []

        try:
            i = 100
            for file_path in tqdm(input_path.glob("*.json")):
                if i <= 0:
                    break
                i -= 1
                with file_path.open("r", encoding="utf-8") as f:
                    data = json.load(f)
                    items = data if isinstance(data, list) else [data]
                    for item_data in items:
                        try:
                            rel = Relationship(**item_data)
                            embedded = self._embed_relationship(rel)
                            results.append(embedded)
                        except Exception as item_error:  # noqa: PERF203
                            msg = f"""Skipping invalid relationship in
                            {file_path.name}: {item_error}"""
                            logger.exception(msg)

            output_path.parent.mkdir(parents=True, exist_ok=True)
            with output_path.open("wb") as f:
                pickle.dump(results, f)

            msg = f"Embedded {len(results)} relationships saved to: {output_file}"
            logger.info(msg)
        except Exception as e:
            msg = f"embed_relationships_from_directory error: {e}"
            logger.exception(msg)


if __name__ == "__main__":
    logger.info("creating embeddings ... It may take a few minutes!!")
    embedder = EntityEmbedder()
    embedder.embed_intrusion_sets_from_directory(
        input_dir=Config.get_instrution_set_path(),
        output_file=Config.get_instrution_set_embedding_file(),
    )
    exit()
    embedder.embed_cve_items_from_directory(
        input_dir=Config.get_cve_path(),
        output_file=Config.get_cve_embedding_file(),
    )

    embedder.embed_attack_patterns_from_directory(
        input_dir=Config.get_attacks_path(),
        output_file=Config.get_attacks_embedding_file(),
    )

    embedder.embed_relationships_from_directory(
        input_dir=Config.get_relations_path(),
        output_file=Config.get_relations_embedding_file(),
    )
