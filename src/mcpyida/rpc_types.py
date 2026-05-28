"""Pydantic models for the mcpy/rpcCallbacks protocol extension."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


# --- mcpy/listFunctions ---


class ListFunctionsParams(BaseModel):
    cursor: str | None = Field(default=None, description='Pagination cursor')


class ListFunctionsRequest(BaseModel):
    method: str = 'mcpy/listFunctions'
    params: ListFunctionsParams = Field(default_factory=ListFunctionsParams)


class FunctionDefinition(BaseModel):
    name: str
    description: str | None = None
    parameterOrder: list[str]
    inputSchema: dict[str, Any]
    returnDescription: str | None = None
    annotations: dict[str, Any] | None = None


class ListFunctionsResult(BaseModel):
    functions: list[FunctionDefinition]
    nextCursor: str | None = None


# --- mcpy/callFunction ---


class CallFunctionParams(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    name: str
    arguments: dict[str, Any] | None = None
    meta: dict[str, Any] | None = Field(default=None, alias='_meta')


class CallFunctionRequest(BaseModel):
    method: str = 'mcpy/callFunction'
    params: CallFunctionParams


class CallFunctionResult(BaseModel):
    content: Any = None


class CallFunctionException(BaseModel):
    type: str
    message: str
    traceback: str | None = None


# --- notifications/mcpy/functions/list_changed ---


class FunctionsChangedNotification(BaseModel):
    method: str = 'notifications/mcpy/functions/list_changed'
