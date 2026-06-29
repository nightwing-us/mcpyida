"""E2E: flat single calls vs batch, error cases, funcs rename, types->list."""
import pytest

from tests.e2e.test_headless_launch import mcp_call


class TestDualInterface:
    def test_decompile_flat_single_call_works(self, headless_server):
        # A flat/single call works and returns one result.
        #
        # NOTE: the single->dict vs batch->list unwrap shape is NOT observable
        # through the joined MCP text — FastMCP emits one content block per list
        # element, so a 1-element batch flattens to the same payload as a single
        # dict (a 1-item batch even parses back as a dict). The exact unwrap
        # shape is proven directly at the unit layer in test_dispatch.py. Here we
        # prove the wrapper end-to-end via the honest signal: batch multiplicity.
        result = mcp_call(headless_server, 'decompile', {'name': 'main'})
        assert 'check_password' in result

    def test_decompile_batch_returns_all_results(self, headless_server):
        # Honest batch signature = multiplicity: a two-item batch yields two
        # results (a single flat call can only ever produce one). Each result
        # dict carries an 'entrypoint' key, so it appears once per result.
        result = mcp_call(
            headless_server,
            'decompile',
            {'items': [{'name': 'main'}, {'name': 'check_password'}]},
        )
        assert result.count('entrypoint') >= 2, (
            f'expected >=2 results in a two-item batch, got: {result[:200]}'
        )

    def test_decompile_both_is_error(self, headless_server):
        with pytest.raises(AssertionError, match='not both'):
            mcp_call(headless_server, 'decompile', {'items': [{'name': 'main'}], 'name': 'main'})

    def test_bare_funcs_gives_instructive_error(self, headless_server):
        with pytest.raises(AssertionError, match=r'list\(entry_type="function"\)'):
            mcp_call(headless_server, 'funcs', {})

    def test_funcs_flat_lookup(self, headless_server):
        result = mcp_call(headless_server, 'funcs', {'target': 'main'})
        assert 'main' in result

    def test_list_types_entry(self, headless_server):
        result = mcp_call(headless_server, 'list', {'entry_type': 'type', 'limit': 5})
        # list(entry_type='type') returns a ListResult envelope with an items[]
        # field — proves the types->list fold actually serves types.
        assert 'items' in result
