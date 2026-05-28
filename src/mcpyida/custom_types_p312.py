from typing import TypeAlias, Union, List, Any, Mapping

JsonValueTypes: TypeAlias = Union[
    str, int, float, bool, None, List[Any], Mapping[str, Any]
]
