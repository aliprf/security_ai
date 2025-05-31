import sys
from pathlib import Path

from utilities.embedding_search import (
    search_attack_embedding,
    search_attack_relations_embedding,
    search_cev_embedding,
    search_intrusion_embedding,
)

project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))


if __name__ == "__main__":
    search_intrusion_embedding(query="login multiple")
    # search_cev_embedding(query="login multiple")
    # search_attack_embedding(query="login multiple")
    # search_attack_relations_embedding(query="login multiple")
