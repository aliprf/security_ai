from __future__ import annotations

import pickle
from operator import itemgetter
from pathlib import Path
from typing import Any

import numpy as np
from pydantic import BaseModel
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity

from commons.attack_patterns import NormalizedAttackPattern
from commons.attack_relationships import Relationship
from commons.cve_items import CVEItem
from commons.embedding_search_response import EmbeddingSearchResponse
from commons.intrusionset import IntrusionSet
from commons.logger import get_logger
from config import Config

logger = get_logger(__name__)


class EmbeddingSearcher:
    def __init__(
        self,
        embedding_file: str,
        model_name: str = "sentence-transformers/all-MiniLM-L6-v2",
    ) -> None:
        self.model = SentenceTransformer(model_name)
        self.embedded_object = self._load_embeddings(embedding_file)

    def _load_embeddings(self, file_path: str) -> list[dict[str, Any]]:  # noqa: PLR6301
        with Path(file_path).open("rb") as f:
            return pickle.load(f)  # noqa: S301

    def _embed_text(self, text: str) -> np.ndarray:
        return self.model.encode(text, convert_to_numpy=True)

    def _search(self, query: str, top_k: int = 5) -> list[tuple[dict[str, Any], float]]:
        query_vec = self._embed_text(query).reshape(1, -1)
        results: list[tuple[dict[str, Any], float]] = []

        for entry in self.embedded_object:
            field_embeddings = list(entry["embeddings"].values())
            avg_embedding = np.mean(np.vstack(field_embeddings), axis=0).reshape(1, -1)
            score = cosine_similarity(query_vec, avg_embedding)[0][0]
            results.append((entry["metadata"], score))

        results.sort(key=itemgetter(1), reverse=True)
        return results[:top_k]


class EmbeddingSearch(EmbeddingSearcher):
    def __init__(
        self,
        embedding_file: str,
        model_name: str = "sentence-transformers/all-MiniLM-L6-v2",
    ) -> None:
        super().__init__(embedding_file, model_name)

    def search(
        self,
        query: str,
        base_model: type[BaseModel],
        top_k: int = 5,
    ) -> list[EmbeddingSearchResponse] | None:
        try:
            results = super()._search(query, top_k)
            response: list[EmbeddingSearchResponse] = []
            for metadata, score in results:
                msg = f"""
                    (Score: {score:.4f})\n
                    {metadata}
                """
                logger.info(msg)
                response.append(
                    EmbeddingSearchResponse(
                        entity=base_model(**metadata),
                        score=score,
                    ),
                )
        except Exception as e:
            msg = f" InstructionsetEmbeddingSearch Exception: search {e}"
            logger.exception(msg)
            return None
        else:
            return response


def search_intrusion_embedding(
    query: str, top_k: int = 5,
) -> list[EmbeddingSearchResponse] | None:
    embedding_file = Config.get_instrution_set_embedding_file()
    try:
        searcher = EmbeddingSearch(embedding_file)
    except Exception as e:
        msg = f" search_intrusion_embeddingonset : {e}"
        logger.exception(msg)
    else:
        return searcher.search(query, base_model=IntrusionSet, top_k=top_k)


def search_cev_embedding(
    query: str, top_k: int = 5,
) -> list[EmbeddingSearchResponse] | None:
    embedding_file = Config.get_cve_embedding_file()
    try:
        searcher = EmbeddingSearch(embedding_file)
    except Exception as e:
        msg = f" search_cev_embedding : {e}"
        logger.exception(msg)
    else:
        return searcher.search(query, base_model=CVEItem, top_k=top_k)


def search_attack_embedding(
    query: str, top_k: int = 5,
) -> list[EmbeddingSearchResponse] | None:
    embedding_file = Config.get_attacks_embedding_file()
    try:
        searcher = EmbeddingSearch(embedding_file)
    except Exception as e:
        msg = f" search_attack_embedding : {e}"
        logger.exception(msg)
    else:
        return searcher.search(query, base_model=NormalizedAttackPattern, top_k=top_k)


def search_attack_relations_embedding(
    query: str, top_k: int = 5,
) -> list[EmbeddingSearchResponse] | None:
    embedding_file = Config.get_relations_embedding_file()
    try:
        searcher = EmbeddingSearch(embedding_file)
    except Exception as e:
        msg = f" search_attack_relations_embedding : {e}"
        logger.exception(msg)
    else:
        return searcher.search(query, base_model=Relationship, top_k=top_k)


if __name__ == "__main__":
    search_intrusion_embedding(query="login multiple")
    search_cev_embedding(query="login multiple")
    search_attack_embedding(query="login multiple")
    search_attack_relations_embedding(query="login multiple")
