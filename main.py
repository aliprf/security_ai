import sys
from pathlib import Path

from utilities.parser import teat_parse_instruction_set, teat_parse_relations, test_nvd, test_parse_attack_patterns

# Add project root to sys.path
project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))


if __name__ == "__main__":
    # test_nvd()
    # test_parse_attack_patterns()
    # teat_parse_relations()
    teat_parse_instruction_set()
