from typing import List, Mapping

type JsonValueTypes = (
    str
    | int
    | float
    | bool
    | None
    | List[JsonValueTypes]
    | Mapping[str, JsonValueTypes]
)
