# ruhusa

A small, dependency-free Attribute-Based Access Control (ABAC) library for Python.

Policies resolve attributes from a request (e.g. `subject.department`, `resource.amount`) using dot paths, with a `MISSING` sentinel for absent values.

## Usage

```python
from abac import resolve, MISSING

request = {"subject": {"department": "finance"}}
resolve("subject.department", request)   # "finance"
resolve("subject.role", request)         # MISSING
```

## Tests

```bash
pytest
```
