from __future__ import annotations

# Standard Libraries
import inspect
import sys
import typing as t
from typing import (
    Annotated,
    get_args,
    get_origin,
)

# Third Party Libraries
from fastapi import (
    Body,
    FastAPI,
)
from pydantic import (
    BaseModel,
    create_model,
    Field,
)


# ---------- helpers ----------

try:
    # pydantic v2
    # Third Party Libraries
    from pydantic.fields import PydanticUndefined
except Exception:
    PydanticUndefined = ...  # type: ignore[assignment]  # best-effort fallback


def _unwrap_annotated(tp):
    if get_origin(tp) is Annotated:
        base, *extras = get_args(tp)
        # Pydantic v2: Field(...) returns FieldInfo
        field_info = next(
            (ex for ex in extras if ex.__class__.__name__ == 'FieldInfo'), None
        )
        return base, field_info
    return tp, None


def _is_optional(tp) -> bool:
    return get_origin(tp) is t.Union and type(None) in get_args(tp)


def _strip_optional(tp):
    if _is_optional(tp):
        return t.Union[tuple(a for a in get_args(tp) if a is not type(None))]  # noqa: E721
    return tp


def _maybe_optionalize(tp, default):
    # If the function default is None but the type isn't Optional, make it Optional
    if default is None and not _is_optional(tp):
        return t.Optional[tp]
    return tp


def build_request_model_from_function(func) -> type[BaseModel]:
    """
    Build a Pydantic v2 request model from a function signature.
    - Preserves defaults (including None) → optional field
    - Respects Annotated[..., Field(...)] metadata
    - Uses '...' only when truly required (no default & not Optional)
    """
    sig = inspect.signature(func)
    hints = t.get_type_hints(func, include_extras=True)

    fields: dict[str, tuple[t.Any, t.Any]] = {}
    for name, param in sig.parameters.items():
        if name in ('self', 'cls'):
            continue

        ann = hints.get(name, t.Any)
        base_ann, annotated_field = _unwrap_annotated(ann)

        base = _strip_optional(base_ann)
        default = (
            param.default if param.default is not inspect._empty else PydanticUndefined
        )

        # If default is None, make type Optional[...] to keep OpenAPI consistent
        base = _maybe_optionalize(base, default)

        if annotated_field is not None:
            # Inject the real default into FieldInfo if it's currently "undefined"
            fi = annotated_field
            if getattr(fi, 'default', PydanticUndefined) is PydanticUndefined:
                # No explicit default set in Field(...), use function default or required
                fi.default = default
            fields[name] = (base, fi)
        else:
            # No Field(...): synthesize one with correct default/requiredness
            if default is PydanticUndefined:
                fields[name] = (base, Field(...))  # required
            else:
                fields[name] = (base, Field(default))  # optional (or has default)

    model_name = f'{func.__name__.capitalize()}Request'
    ReqModel = create_model(model_name, **fields)  # type: ignore[arg-type, call-overload]
    # Help FastAPI/Pydantic resolve it like a top-level class
    ReqModel.__module__ = getattr(func, '__module__', '__main__')
    try:
        ReqModel.model_rebuild(force=True)
    except Exception:
        pass
    return ReqModel


def response_model_from_return_type(func) -> tuple[type[BaseModel] | None, bool]:
    """
    If the function’s return type is a Pydantic BaseModel subclass, use it directly.
    Otherwise return None and we’ll wrap the value as {"result": ...}.
    The bool indicates whether the function is annotated at all.
    """
    hints = t.get_type_hints(func, include_extras=True)
    rt = hints.get('return')
    if rt is None:
        return None, False
    try:
        if inspect.isclass(rt) and issubclass(rt, BaseModel):
            return rt, True
    except Exception:
        pass
    return None, True


def _doc_summary_and_desc(func) -> tuple[str | None, str | None]:
    doc = inspect.getdoc(func) or ''
    if not doc:
        return None, None
    lines = doc.strip().splitlines()
    summary = lines[0].strip()
    desc = '\n'.join(line.rstrip() for line in lines[1:]).strip() or None
    return summary, desc


# ---------- the decorator factory ----------


def as_openapi_tool(
    app: FastAPI, *, route_prefix='/tools', tags=None, name: str | None = None
):
    def _decorator(func):
        # --- build the request model dynamically ---
        ReqModel = build_request_model_from_function(func)  # your helper

        # Give it a stable, importable identity
        module_name = getattr(func, '__module__', '__main__')
        model_name = f'{func.__name__.capitalize()}Request'
        ReqModel.__name__ = model_name
        ReqModel.__qualname__ = model_name
        ReqModel.__module__ = module_name

        # Register into the defining module's globals so forward refs can resolve
        module = sys.modules[module_name]
        setattr(module, model_name, ReqModel)

        # Rebuild to resolve any forward refs
        try:
            ReqModel.model_rebuild(force=True)
        except Exception:
            pass

        RespModel, _ = response_model_from_return_type(func)  # your helper
        tool_name = name or func.__name__
        path = f'{route_prefix}/{tool_name}'
        summary, description = _doc_summary_and_desc(func)  # your helper
        is_async = inspect.iscoroutinefunction(func)

        async def endpoint(payload: ReqModel = Body(...)):  # type: ignore[name-defined]
            kwargs = payload.model_dump()  # type: ignore[attr-defined]
            result = await func(**kwargs) if is_async else func(**kwargs)
            return result if RespModel is not None else {'result': result}

        # CRITICAL: replace the forward-ref string with the actual class object
        endpoint.__annotations__ = dict(endpoint.__annotations__)
        endpoint.__annotations__['payload'] = ReqModel
        endpoint.__name__ = f'{tool_name}_endpoint'

        app.post(
            path,
            name=tool_name,
            operation_id=tool_name,
            tags=tags or ['mcp-tools'],
            summary=summary,
            description=description,
            response_model=RespModel,  # can be None
        )(endpoint)

        return func

    return _decorator
