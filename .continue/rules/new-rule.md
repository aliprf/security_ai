---
description: Enforce Python best practices in code generation. All output must be valid Python 3 code with correct type hints, clear comments, and properly formatted docstrings. Code must pass both Pylance (type-checking) and Ruff (linting/formatting) checks.
---

# Python Code Assistant Rule

## Objective
Produce production-quality Python code that is:
- Correct and executable.
- Type-safe and Pylance-compliant.
- Clean, readable, and Ruff-compliant.
- Fully documented with docstrings and inline comments.

## Code Quality Standards

### ✅ Validity
- Code must run without syntax or runtime errors.
- All functions and classes must include type annotations that pass **Pylance** (`mypy`-like).

### ✅ Documentation
- Every function, class, and module must include a **valid docstring**.
- Use `"""Triple-quoted docstrings"""` following [PEP 257](https://peps.python.org/pep-0257/).
- Include parameter types and return descriptions in the docstring.
- Use Google or NumPy docstring style unless otherwise requested.

### ✅ Comments
- Include **meaningful inline comments** for non-obvious logic.
- Comments should explain the why, not just the what.

### ✅ Style
- Code must follow [Ruff](https://docs.astral.sh/ruff/) standards:
  - PEP 8 compliant formatting.
  - Sorted and grouped imports (`isort` style).
  - Compatible with `black` formatter by default.
  - No unused imports, unreachable code, or shadowed variables.
  - No unnecessary type ignores or broad exception handling.

### ✅ Typing
- Use precise Python 3.10+ types:
  - Use `list[int]`, not `List[int]` (unless using `from __future__ import annotations`).
  - Use `Optional`, `Union`, `Literal`, `TypedDict`, and `Protocol` as needed.
  - Avoid `Any` unless necessary.

## Example Response Pattern

### Input:
“Write a function that returns the factorial of a number”

### Output:
```python
from typing import Union

def factorial(n: int) -> int:
    """
    Compute the factorial of a non-negative integer.

    Args:
        n (int): A non-negative integer.

    Returns:
        int: The factorial of the input number.

    Raises:
        ValueError: If the input is negative.
    """
    if n < 0:
        raise ValueError("Input must be non-negative")

    result: int = 1
    for i in range(2, n + 1):
        result *= i  # Multiply result by current number

    return result
