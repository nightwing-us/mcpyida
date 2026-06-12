"""Live check: a self write-tool (mcp.self.rename) commits via the in-process
path (GUI MFF_WRITE direct call) with ctx=None (elicitation auto-allowed), and
fully reverts. Self-reverting — leaves the database unchanged.

Run against a RUNNING MCPyIDA server (real IDA):
    MCPYIDA_URL=http://127.0.0.1:6150/mcp python3 -m tests.e2e.exercise_self_write
"""
from __future__ import annotations

import json
import os

import anyio
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamablehttp_client

URL = os.environ.get('MCPYIDA_URL', 'http://127.0.0.1:6150/mcp')

# Renames the first function twice via mcp.self.rename — the 2nd rename overwrites
# a *user* name, exercising elicit_confirmation_sync's ctx=None auto-allow path —
# then reverts. Revert clears the name for auto-named functions (restoring the
# auto name) and restores the exact string for user-named ones; it uses
# SN_NOCHECK and never re-sets a reserved prefix (e.g. 'sub_'), which would pop a
# modal Warning dialog and wedge the GUI.
CODE = r"""
import idautils, ida_bytes, ida_name
_funcs = list(idautils.Functions())
assert _funcs, 'no functions in database'
_ea = _funcs[0]
_flags = ida_bytes.get_full_flags(_ea)
_orig = ida_name.get_ea_name(_ea)
_was_user = bool(ida_bytes.has_user_name(_flags))
_r1 = mcp.self.rename(items=[{'addr': hex(_ea), 'new_name': 'mcpself_wtest_A'}])
_after1 = ida_name.get_ea_name(_ea)
_r2 = mcp.self.rename(items=[{'addr': hex(_ea), 'new_name': 'mcpself_wtest_B'}])
_after2 = ida_name.get_ea_name(_ea)
ida_name.set_name(_ea, _orig if _was_user else '', ida_name.SN_NOCHECK)
_restored = ida_name.get_ea_name(_ea)
result = {
    'ea': hex(_ea),
    'orig': _orig,
    'was_user': _was_user,
    'after1': _after1,
    'after2': _after2,
    'restored': _restored,
    'write1_commit_ok': _after1 == 'mcpself_wtest_A',
    'write2_overwrite_user_ok': _after2 == 'mcpself_wtest_B',
    'reverted': _restored == _orig,
    'r1': str(_r1)[:160],
    'r2': str(_r2)[:160],
}
result
"""


async def _run() -> dict:
    async with streamablehttp_client(URL) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            with anyio.fail_after(30):
                result = await session.call_tool('idapython', {'code': CODE, 'reset': True})
    texts = [i.text for i in result.content if hasattr(i, 'text')]
    for t in texts:
        try:
            return json.loads(t)
        except (json.JSONDecodeError, ValueError):
            continue
    return {'success': False, 'error': f'no JSON in {texts!r}', 'isError': result.isError}


def main() -> None:
    print(f'Self write-tool check vs {URL}')
    data = anyio.run(_run)
    print(json.dumps(data, indent=2)[:1200])
    res = data.get('result')
    print(f'\nsuccess={data.get("success")} error={data.get("error")!r}')
    print(f'(committed + reverted expected True/True; DB left unchanged)')


if __name__ == '__main__':
    main()
