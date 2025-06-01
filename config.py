ENV_FILE = ".env"

prefix = "data/"
raw_cve_path = prefix + "nvd/nvdcve-1.1-2025.json"
raw_instruction_set_path = prefix + "cti/intrusion-set/"
raw_attack_path = prefix + "cti/attack-pattern/"
raw_relations_path = prefix + "cti/relationships/"


processed_prefix = "data/proccessed/"
cve_path = processed_prefix + "nvd/"
instruction_set_path = processed_prefix + "intrusion-set/"
attack_path = processed_prefix + "attacks/"
relations_path = processed_prefix + "relations/"

embedding_prefix = "data/embeddings/"
cve_path_embedding_file = embedding_prefix + "nvd.pkl"
instruction_set_path_embedding_file = embedding_prefix + "intrusion-set.pkl"
attack_path_embedding_file = embedding_prefix + "attacks.pkl"
relations_path_embedding_file = embedding_prefix + "relations.pkl"


class Config:
    @classmethod
    def _get_env_value(cls, key: str = "env") -> str:
        try:
            with open(ENV_FILE) as f:
                for line in f:
                    line = line.strip()
                    if line.startswith(f"{key}="):
                        return line.split("=", 1)[1].strip().strip('"').strip("'")
        except FileNotFoundError as e:
            raise FileNotFoundError from e
        msg = f"key not found in {ENV_FILE}"
        raise ValueError(msg)

    @classmethod
    def get_model_name(cls) -> str:
        return "gpt-4.1-nano"

    @classmethod
    def get_raw_cve_path(cls) -> str:
        return raw_cve_path

    @classmethod
    def get_raw_instrution_set_path(cls) -> str:
        return raw_instruction_set_path

    @classmethod
    def get_raw_attacks_path(cls) -> str:
        return raw_attack_path

    @classmethod
    def get_raw_relations_path(cls) -> str:
        return raw_relations_path

    @classmethod
    def get_cve_path(cls) -> str:
        return cve_path

    @classmethod
    def get_instrution_set_path(cls) -> str:
        return instruction_set_path

    @classmethod
    def get_attacks_path(cls) -> str:
        return attack_path

    @classmethod
    def get_relations_path(cls) -> str:
        return relations_path

    @classmethod
    def get_cve_embedding_file(cls) -> str:
        return cve_path_embedding_file

    @classmethod
    def get_instrution_set_embedding_file(cls) -> str:
        return instruction_set_path_embedding_file

    @classmethod
    def get_attacks_embedding_file(cls) -> str:
        return attack_path_embedding_file

    @classmethod
    def get_relations_embedding_file(cls) -> str:
        return relations_path_embedding_file
