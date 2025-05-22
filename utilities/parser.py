from datetime import datetime
import json
import os
from pathlib import Path
from typing import Any
from commons.attack_patterns import (
    AdversaryDifficulty,
    DefenseDetectability,
    ExternalReference,
    KillChainPhase,
    NormalizedAttackPattern,
)
from commons.attack_relationships import Relationship
from commons.logger import get_logger

from config import Config

logger = get_logger(__name__)


class DataParser:
    @classmethod
    def parse_nvd(cls, input_address_path: str, outpout_address_path: str):
        try:
            input_path = Path(input_address_path)
            output_path = Path(outpout_address_path)

            with open(input_path, "r") as f:
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

                with open(output_path / f"{cve_id}.json", "w") as f:
                    json.dump(flat_item, f, indent=2)

        except Exception as e:
            raise Exception("Failed to parse NVD data") from e

    @classmethod
    def parse_attack_patterns(cls, input_path_address: str, output_path_address: str):
        input_path = Path(input_path_address)
        output_path = Path(output_path_address)
        output_path.mkdir(parents=True, exist_ok=True)

        parsed_items: list[NormalizedAttackPattern] = []

        for file_name in os.listdir(input_path):
            file_path = input_path / file_name
            if not file_path.is_file() or not file_name.endswith(".json"):
                continue

            with open(file_path, "r", encoding="utf-8") as f:
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
                    kill_chain=KillChainPhase(
                        name=obj["kill_chain_phases"][0]["kill_chain_name"],
                        phase=obj["kill_chain_phases"][0]["phase_name"],
                    )
                    if obj.get("kill_chain_phases")
                    else None,
                    detectable_by_defense=DefenseDetectability(
                        status=obj.get("x_mitre_detectable_by_common_defenses"),
                        explanation=obj.get(
                            "x_mitre_detectable_by_common_defenses_explanation"
                        ),
                    )
                    if obj.get("x_mitre_detectable_by_common_defenses")
                    else None,
                    adversary_difficulty=AdversaryDifficulty(
                        status=obj.get("x_mitre_difficulty_for_adversary"),
                        explanation=obj.get(
                            "x_mitre_difficulty_for_adversary_explanation"
                        ),
                    )
                    if obj.get("x_mitre_difficulty_for_adversary")
                    else None,
                    deprecated=obj.get("x_mitre_deprecated", False),
                    version=obj.get("x_mitre_version"),
                    created=datetime.fromisoformat(
                        obj["created"].replace("Z", "+00:00")
                    )
                    if "created" in obj
                    else None,
                    modified=datetime.fromisoformat(
                        obj["modified"].replace("Z", "+00:00")
                    )
                    if "modified" in obj
                    else None,
                )

                parsed_items.append(attack_pattern)

                # Save individual file
                with open(
                    output_path / f"{attack_pattern.id}.json", "w", encoding="utf-8"
                ) as out_f:
                    out_f.write(attack_pattern.model_dump_json(indent=2))   
    @classmethod
    def parse_relationships(cls, input_path_address: str, output_path_address: str):
        input_path = Path(input_path_address)
        output_path = Path(output_path_address)
        rel_dir = output_path / "relationships"
        rel_dir.mkdir(parents=True, exist_ok=True)

        items: list[Relationship] = []

        for filename in os.listdir(input_path):
            file_path = input_path / filename
            if not file_path.is_file() or not filename.endswith(".json"):
                continue

            with open(file_path, "r") as f:
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
                        ] if obj.get("external_references") else None,
                        created=obj.get("created"),
                        modified=obj.get("modified")
                    )
                    items.append(model)

        for item in items:
            with open(rel_dir / f"{item.id}.json", "w") as f:
                f.write(item.model_dump_json(indent=2))


def teat_parse_relations():
    input_file: str = Config.get_raw_relations_path()
    output_dir: str = Config.get_relations_path()

    DataParser.parse_relationships(
        input_path_address=input_file,
        output_path_address=output_dir
    )

def test_parse_attack_patterns():
    input_file: str = Config.get_raw_attacks_path()
    output_dir: str = Config.get_attacks_path()

    DataParser.parse_attack_patterns(
        input_path_address=input_file,
        output_path_address=output_dir
    )


def test_nvd():
    input_file: str = Config.get_raw_cve_path()
    output_dir: str = Config.get_cve_path()

    DataParser.parse_nvd(input_address_path=input_file, outpout_address_path=output_dir)


if __name__ == "__main__":
    test_nvd()
