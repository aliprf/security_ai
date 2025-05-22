import sys
from pathlib import Path

# Add project root to sys.path
project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))


from utilities.parser import teat_parse_relations, test_nvd, test_parse_attack_patterns

if __name__ == "__main__":
    teat_parse_relations()
    test_parse_attack_patterns()
    test_nvd()
