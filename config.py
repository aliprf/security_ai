
ENV_FILE = ".env"

prefix="data/"
raw_cve_path=prefix+"nvd/nvdcve-1.1-2025.json"
raw_attack_path= prefix+"cti/attack-pattern/"
raw_relations_path= prefix+"cti/relationships/"


processed_prefix="data/proccessed/"
cve_path=processed_prefix+"nvd/"
attack_path= processed_prefix+ "attacks/"
relations_path= processed_prefix+("relations/")

class Config:
    @classmethod
    def _get_env_value(cls, key: str = "env") -> str:
        try:
            with open(ENV_FILE, "r") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith(f"{key}="):
                        value = line.split("=", 1)[1].strip().strip('"').strip("'")
                        return value
        except FileNotFoundError as e:
            raise FileNotFoundError from e
        msg= f"key not found in {ENV_FILE}"
        raise ValueError(msg)

    @classmethod
    def get_raw_cve_path(cls)-> str:
        return raw_cve_path
    
    @classmethod 
    def get_raw_attacks_path(cls) -> str:
        return raw_attack_path
    
    @classmethod
    def get_raw_relations_path(cls) -> str:
        return raw_relations_path
    
    @classmethod
    def get_cve_path(cls)-> str:
        return cve_path
    
    @classmethod 
    def get_attacks_path(cls) -> str:
        return attack_path
    
    @classmethod
    def get_relations_path(cls) -> str:
        return relations_path