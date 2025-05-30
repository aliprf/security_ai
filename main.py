import sys
from pathlib import Path

from config import Config
from utilities.embedding_creator import EntityEmbedder

project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))


if __name__ == "__main__":
    embedder = EntityEmbedder()
    embedder.embed_intrusion_sets_from_directory(
        input_dir=Config.get_instrution_set_path(),
        output_file=Config.get_instrution_set_embedding_file(),
    )
    pass
