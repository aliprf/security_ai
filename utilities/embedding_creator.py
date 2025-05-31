import json
import pickle
from pathlib import Path
from typing import Any

from numpy import ndarray
from pydantic import BaseModel
from sentence_transformers import SentenceTransformer
from tqdm import tqdm

from commons.attack_patterns import NormalizedAttackPattern
from commons.attack_relationships import Relationship
from commons.cve_items import CVEItem
from commons.intrusionset import IntrusionSet
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
    def _embed_json_set(self, obj: BaseModel) -> dict[str, Any]:
        extracted = obj.model_dump()
        return {
            "embeddings": {
                k: self._embed_text(str(v)) for k, v in extracted.items() if k != "id"
            },
            "metadata": extracted,
        }

    def embed_from_directory(
        self,
        input_dir: str,
        output_file: str,
        base_model: type[BaseModel],
    ) -> None:
        input_path = Path(input_dir)
        output_path = Path(output_file)
        results = []

        try:
            for file_path in tqdm(input_path.glob("*.json")):
                with file_path.open("r", encoding="utf-8") as f:
                    data = json.load(f)
                    try:
                        intrusion_set = base_model(**data)
                        embedded = self._embed_json_set(intrusion_set)
                        results.append(embedded)
                    except Exception as item_error:
                        msg = f"""Skipping invalid bundle in
                        {file_path.name}: {item_error}"""
                        logger.exception(msg)

            output_path.parent.mkdir(parents=True, exist_ok=True)
            with output_path.open("wb") as f:
                pickle.dump(results, f)

            msg = f"Embedded {len(results)} saved to: {output_file}"
            logger.info(msg)
        except Exception as e:
            msg = f"embed_intrusion_sets_from_directory error: {e}"
            logger.exception(msg)


if __name__ == "__main__":
    logger.info("creating embeddings ... It may take a few minutes!!")
    embedder = EntityEmbedder()
    embedder.embed_from_directory(
        input_dir=Config.get_instrution_set_path(),
        output_file=Config.get_instrution_set_embedding_file(),
        base_model=IntrusionSet,
    )

    embedder.embed_from_directory(
        input_dir=Config.get_cve_path(),
        output_file=Config.get_cve_embedding_file(),
        base_model=CVEItem,
    )

    embedder.embed_from_directory(
        input_dir=Config.get_attacks_path(),
        output_file=Config.get_attacks_embedding_file(),
        base_model=NormalizedAttackPattern,
    )

    embedder.embed_from_directory(
        input_dir=Config.get_relations_path(),
        output_file=Config.get_relations_embedding_file(),
        base_model=Relationship,
    )
