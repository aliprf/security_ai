from vec_db.chroma_client import ChromaAttackDB


def semantic_search(collection, query: str, top_k: int = 5):
    results = collection.query(
        query_texts=[query],
        n_results=top_k,
    )
    return results


def tool_attack_patterns(db: ChromaAttackDB, query: str):
    coll = db.get_collection("attack_patterns")
    return semantic_search(coll, query)


def tool_intrusion_sets(db: ChromaAttackDB, query: str):
    coll = db.get_collection("intrusion_sets")
    return semantic_search(coll, query)


def tool_cves(db: ChromaAttackDB, query: str):
    coll = db.get_collection("cves")
    return semantic_search(coll, query)


def tool_relationships(db: ChromaAttackDB, query: str):
    coll = db.get_collection("relationships")
    return semantic_search(coll, query)
