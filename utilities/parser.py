from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, TypeVar

from commons.attack_patterns import (
    AdversaryDifficulty,
    DefenseDetectability,
    ExternalReference,
    KillChainPhase,
    NormalizedAttackPattern,
)
from commons.attack_relationships import Relationship
from commons.instruction_bundle import IntrusionSet, IstructionBundle
from commons.logger import get_logger
from config import Config

logger = get_logger(__name__)

BundleType = TypeVar("BundleType", bound="IstructionBundle")


class DataParser:
    @classmethod
    def parse_bundle_and_save_each(
        cls,
        input_path_address: str,
        output_path_address: str,
    ) -> None:
        input_path = Path(input_path_address)
        output_path = Path(output_path_address)
        output_path.mkdir(parents=True, exist_ok=True)

        with input_path.open("r", encoding="utf-8") as f:
            data = json.load(f)

        for obj in data.get("objects", []):
            if obj.get("type") != "intrusion-set":
                continue

            def parse_dt(dt_str: str) -> datetime | None:
                return datetime.fromisoformat(dt_str.replace("Z", "+00:00")) if dt_str else None

            external_refs = [ExternalReference(**ref) for ref in obj.get("external_references", [])]

            intrusion_set = IntrusionSet(
                type=obj["type"],  # <-- include this
                id=obj["id"],
                name=obj["name"],
                description=obj["description"],
                aliases=obj.get("aliases", []),
                x_mitre_deprecated=obj.get("x_mitre_deprecated", False),
                x_mitre_version=obj.get("x_mitre_version", ""),
                modified=parse_dt(obj.get("modified")),
                created=parse_dt(obj.get("created")),
                created_by_ref=obj["created_by_ref"],
                revoked=obj.get("revoked", False),
                external_references=external_refs,
                object_marking_refs=obj.get("object_marking_refs", []),
                x_mitre_domains=obj.get("x_mitre_domains", []),
                x_mitre_attack_spec_version=obj.get("x_mitre_attack_spec_version", ""),
                x_mitre_modified_by_ref=obj.get("x_mitre_modified_by_ref", ""),
                x_mitre_contributors=obj.get("x_mitre_contributors"),
            )

            # Save individual intrusion set JSON file
            output_file = output_path / f"{intrusion_set.id}.json"
            with output_file.open("w", encoding="utf-8") as out_f:
                out_f.write(intrusion_set.model_dump_json(indent=2))

    @classmethod
    def parse_nvd(cls, input_address_path: str, outpout_address_path: str) -> None:
        try:
            input_path = Path(input_address_path)
            output_path = Path(outpout_address_path)

            with input_path.open("r", encoding="utf-8") as f:
                data = json.load(f)

            output_path.mkdir(parents=True, exist_ok=True)

            for item in data.get("CVE_Items", []):
                cve_id = (
                    item.get("cve", {}).get("CVE_data_meta", {}).get("ID", "UNKNOWN")
                )
                logger.info("Processing CVE item: %s", cve_id)

                description_data = (
                    item.get("cve", {})
                    .get("description", {})
                    .get("description_data", [])
                )
                description = description_data[0]["value"] if description_data else ""

                references = [
                    ref.get("url", "")
                    for ref in item.get("cve", {})
                    .get("references", {})
                    .get("reference_data", [])
                ]

                impact_data = item.get("impact", {}).get("baseMetricV3", {})
                severity = impact_data.get("cvssV3", {}).get("baseSeverity", "UNKNOWN")
                exploitability_score = impact_data.get("exploitabilityScore", 0.0)
                impact_score = impact_data.get("impactScore", 0.0)

                flat_item: dict[str, Any] = {
                    "cve_id": cve_id,
                    "description": description,
                    "published_date": item.get("publishedDate", ""),
                    "last_modified_date": item.get("lastModifiedDate", ""),
                    "severity": severity,
                    "exploitability_score": exploitability_score,
                    "impact_score": impact_score,
                    "references": references,
                }

                output_file: Path = output_path / f"{cve_id}.json"
                with output_file.open("w", encoding="utf-8") as f:
                    json.dump(flat_item, f, indent=2)

        except Exception as e:
            msg = "Failed to parse NVD data"
            raise Exception(msg) from e

    @classmethod
    def parse_attack_patterns(
        cls,
        input_path_address: str,
        output_path_address: str,
    ) -> None:
        input_path = Path(input_path_address)
        output_path = Path(output_path_address)
        output_path.mkdir(parents=True, exist_ok=True)

        parsed_items: list[NormalizedAttackPattern] = []

        input_path = Path(input_path)
        for file_name in input_path.iterdir():
            if file_name.is_file() and file_name.suffix == ".json":
                with file_name.open("r", encoding="utf-8") as f:
                    data = json.load(f)

                for obj in data.get("objects", []):
                    if obj.get("type") != "attack-pattern":
                        continue

                    external_id = None
                    source_url = None
                    for ref in obj.get("external_references", []):
                        if ref.get("source_name") == "mitre-attack":
                            external_id = ref.get("external_id")
                            source_url = ref.get("url")
                            break

                    attack_pattern = NormalizedAttackPattern(
                        id=obj["id"],
                        name=obj["name"],
                        description=obj.get("description"),
                        external_id=external_id,
                        source_url=source_url,
                        kill_chain=(
                            KillChainPhase(
                                name=obj["kill_chain_phases"][0]["kill_chain_name"],
                                phase=obj["kill_chain_phases"][0]["phase_name"],
                            )
                            if obj.get("kill_chain_phases")
                            else None
                        ),
                        detectable_by_defense=(
                            DefenseDetectability(
                                status=obj.get("x_mitre_detectable_by_common_defenses"),
                                explanation=obj.get(
                                    "x_mitre_detectable_by_common_defenses_explanation",
                                ),
                            )
                            if obj.get("x_mitre_detectable_by_common_defenses")
                            else None
                        ),
                        adversary_difficulty=(
                            AdversaryDifficulty(
                                status=obj.get("x_mitre_difficulty_for_adversary"),
                                explanation=obj.get(
                                    "x_mitre_difficulty_for_adversary_explanation",
                                ),
                            )
                            if obj.get("x_mitre_difficulty_for_adversary")
                            else None
                        ),
                        deprecated=obj.get("x_mitre_deprecated", False),
                        version=obj.get("x_mitre_version"),
                        created=(
                            datetime.fromisoformat(
                                obj["created"].replace("Z", "+00:00"),
                            )
                            if "created" in obj
                            else None
                        ),
                        modified=(
                            datetime.fromisoformat(
                                obj["modified"].replace("Z", "+00:00"),
                            )
                            if "modified" in obj
                            else None
                        ),
                    )

                    parsed_items.append(attack_pattern)

                    # Save individual file
                    output_file = output_path / f"{attack_pattern.id}.json"
                    with output_file.open("w", encoding="utf-8") as out_f:
                        out_f.write(attack_pattern.model_dump_json(indent=2))

    @classmethod
    def parse_relationships(
        cls,
        input_path_address: str,
        output_path_address: str,
    ) -> None:
        input_path = Path(input_path_address)
        output_path = Path(output_path_address)
        rel_dir = output_path / "relationships"
        rel_dir.mkdir(parents=True, exist_ok=True)

        items: list[Relationship] = []

        for file_path in input_path.iterdir():
            if not file_path.is_file() or file_path.suffix != ".json":
                continue

            with file_path.open("r", encoding="utf-8") as f:
                data = json.load(f)

            for obj in data.get("objects", []):
                if obj.get("type") == "relationship":
                    model = Relationship(
                        id=obj["id"],
                        type=obj["type"],
                        source_ref=obj["source_ref"],
                        target_ref=obj["target_ref"],
                        relationship_type=obj["relationship_type"],
                        description=obj.get("description"),
                        created_by_ref=obj.get("created_by_ref"),
                        object_marking_refs=obj.get("object_marking_refs"),
                        external_references=[
                            ExternalReference(**ref)
                            for ref in obj.get("external_references", [])
                        ]
                        if obj.get("external_references")
                        else None,
                        created=obj.get("created"),
                        modified=obj.get("modified"),
                    )
                    items.append(model)

        for item in items:
            output_file = rel_dir / f"{item.id}.json"
            with output_file.open("w", encoding="utf-8") as f:
                f.write(item.model_dump_json(indent=2))


def teat_parse_instruction_set() -> None:
    input_file: str = Config.get_raw_instrution_set_path()
    output_dir: str = Config.get_instrution_set_path()

    DataParser.parse_bundle_and_save_each(
        input_path_address=input_file,
        output_path_address=output_dir,
    )


def teat_parse_relations() -> None:
    input_file: str = Config.get_raw_relations_path()
    output_dir: str = Config.get_relations_path()

    DataParser.parse_relationships(
        input_path_address=input_file,
        output_path_address=output_dir,
    )


def test_parse_attack_patterns() -> None:
    input_file: str = Config.get_raw_attacks_path()
    output_dir: str = Config.get_attacks_path()

    DataParser.parse_attack_patterns(
        input_path_address=input_file,
        output_path_address=output_dir,
    )


def test_nvd() -> None:
    input_file: str = Config.get_raw_cve_path()
    output_dir: str = Config.get_cve_path()

    DataParser.parse_nvd(input_address_path=input_file, outpout_address_path=output_dir)
