import chromadb
from chromadb.config import Settings

chroma_settings = Settings(
    chroma_db_impl="duckdb+parquet",
    persist_directory="./chroma-attackdb",
    chroma_server_host="localhost",
    chroma_server_http_port=8000,
    chroma_server_ws_port=8001,
    index_impl="faiss",
)


class ChromaAttackDB:
    def __init__(self, persist_dir: str):
        self.client = chromadb.Client(
            Settings(
                chroma_db_impl="duckdb+parquet",
                persist_directory=persist_dir,
                index_impl="faiss",
            ),
        )

        self.collections = {}
        self.base_models = [
            "attack_patterns",
            "intrusion_sets",
            "cves",
            "relationships",
        ]

        for model_name in self.base_models:
            try:
                collection = self.client.get_collection(name=model_name)
            except Exception:
                collection = self.client.create_collection(
                    name=model_name, embedding_function=None,
                )
            self.collections[model_name] = collection

    def get_collection(self, name: str):
        if name not in self.collections:
            raise ValueError(f"Collection '{name}' not found")
        return self.collections[name]

    def add_items(
        self, collection_name: str, ids: list, documents: list, embeddings: list,
    ):
        """Add items to the specified collection, embeddings must be provided."""
        collection = self.get_collection(collection_name)
        collection.add(
            ids=ids,
            documents=documents,
            embeddings=embeddings,
        )
