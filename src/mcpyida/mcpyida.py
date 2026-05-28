# Standard Libraries
from abc import (
    ABC,
    abstractmethod,
)
from importlib.metadata import version
import logging
import sys
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    NewType,
    Optional,
    Union,
)
import warnings

from .mcpserver import (
    McpServer,
    McpServerState,
)


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Module-level singleton to ensure all plugin instances share the same server
_mcp_server: McpServer | None = None


# if sys.version_info < (3, 11):
#     # Third Party Libraries
#     from exceptiongroup import ExceptionGroup


if sys.version_info < (3, 8):
    warnings.warn('Python 3.8 or higher is required for ' + __name__)

else:
    # Third Party Libraries
    import ida_idp
    import ida_kernwin
    import ida_nalt
    import idaapi

    IconId = NewType('IconId', int)

    class IdaActionBase(idaapi.action_handler_t, ABC):  # type: ignore
        def __init__(
            self,
            action_name: str,
            display_name: str,
            menu_path: str = '',
            main_menu_path: str = 'Edit',
            description: str = '',
            hotkey: str = '',
            icon: IconId = IconId(0),
        ) -> None:
            idaapi.action_handler_t.__init__(self)
            self.menu_path = menu_path
            self.base_mainmenu_path = main_menu_path
            self.name = action_name
            self.display_name = display_name
            self.hotkey = hotkey
            self.description = description

            self._registered = False
            self._action_desc = idaapi.action_desc_t(
                self.name,  # Action unique ID
                self.display_name,
                self,
                self.hotkey,
                self.description,
                icon,
            )

        @abstractmethod
        def activate(self, ctx: Any) -> int: ...

        @abstractmethod
        def update(self, ctx: Any) -> int:
            """
            Possible return values:

            idaapi.AST_ENABLE_ALWAYS - Enable action permanently. Never call update again.
            idaapi.AST_ENABLE_FOR_IDB - Enable action for current IDB. Call update() again when database is opened/closed
            idaapi.AST_ENABLE_FOR_WIDGET - Enable for current widget. Call update() again when widget gains/loses focus
            idaapi.AST_ENABLE - Enable. Call update() when anything changes
            idaapi.AST_DISABLE_ALWAYS - Disable action permanently. Never call update again.
            idaapi.AST_DISABLE_FOR_IDB - Disable action for current IDB. Call update() when database is opened/closed
            idaapi.AST_DISABLE_FOR_WIDGET - Disable for current widget. Call update() when widget gains/loses focus
            idaapi.AST_DISABLE - Disable. Call update() when anything changes

            :param ctx:
            :return:
            """
            ...

        def register(self) -> None:
            if not self._registered:
                idaapi.register_action(self._action_desc)
                idaapi.attach_action_to_menu(
                    f'{self.base_mainmenu_path}/{self.menu_path}',
                    self.name,
                    idaapi.SETMENU_FIRST,
                )

        def register_context_menu(self, form: Any, popup: Any) -> None:
            logger.info(
                f'Registering {self.display_name} - {self.name} - {self.menu_path}'
            )
            idaapi.attach_action_to_popup(form, popup, self.name, self.menu_path)

        def unregister(self) -> None:
            if self._registered:
                idaapi.detach_action_from_menu(self.menu_path, self.name)
                idaapi.unregister_action(self._action_desc)

        def on_main_thread(
            self,
            func: Union[Callable[..., None], Callable[..., Any]],
            args: Iterable[Any] = tuple(),
            kwargs: Optional[Dict[str, Any]] = None,
        ) -> Optional[Any]:
            ret_val: List[Any] = [None]
            if kwargs is None:
                kwargs = {}

            def caller() -> int:
                ret_val[0] = func(*args, **kwargs)
                return 1

            idaapi.execute_sync(caller, idaapi.MFF_WRITE)
            return ret_val[0]

    class IdaCallableAction(IdaActionBase):
        def __init__(
            self,
            exec_func: Callable[[Any], int],
            action_name: str,
            display_name: str,
            menu_path: str = '',
            main_menu_path: str = 'Edit',
            description: str = '',
            hotkey: str = '',
            icon: IconId = IconId(0),
            update_func: Optional[Callable[[Any], int]] = None,
        ) -> None:
            super().__init__(
                action_name,
                display_name,
                menu_path,
                main_menu_path,
                description,
                hotkey,
                icon,
            )
            self._exec_func = exec_func
            self._update_func = update_func

        def activate(self, ctx: Any) -> int:
            return self._exec_func(ctx)

        def update(self, ctx: Any) -> int:
            if self._update_func is not None:
                return self._update_func(ctx)
            return int(idaapi.AST_ENABLE_ALWAYS)

    MENU_PATH = 'MCP Server/'

    class _UiHooks(ida_kernwin.UI_Hooks):
        def __init__(
            self,
            ui_ready_handler: Callable[[], None] | None = None,
            db_init: Callable[[bool], None] | None = None,
            db_closed: Callable[[], None] | None = None,
        ) -> None:
            super().__init__()
            self._ui_ready_handler = ui_ready_handler
            self._db_init = db_init
            self._db_closed = db_closed

        def database_inited(self, is_new_db, _) -> None:
            if self._db_init is not None:
                self._db_init(is_new_db)

        def database_closed(self):
            if self._db_closed is not None:
                self._db_closed()

        def ready_to_run(self):
            if self._ui_ready_handler:
                self._ui_ready_handler()

    class _IdbHooks(ida_idp.IDB_Hooks):
        def __init__(
            self,
            analysis_complete_handler: Callable[[], None] | None = None,
            idb_closing_handler: Callable[[], None] | None = None,
        ) -> None:
            super().__init__()
            self._idb_closing_handler = idb_closing_handler
            self._analysis_complete_handler = analysis_complete_handler

        def auto_empty(self) -> None:
            if self._analysis_complete_handler:
                self._analysis_complete_handler()

        def closebase(self) -> None:
            if self._idb_closing_handler:
                self._idb_closing_handler()

    class MCPyIdaPlugMod(idaapi.plugmod_t):
        def __init__(self):
            global _mcp_server

            version_str = version('mcpyida')
            print(f'MCPyIDA Plugin {version_str}')

            # Use module-level singleton to share server across all plugin instances
            if _mcp_server is None:
                _mcp_server = McpServer()
            self._mcp_server = _mcp_server

            self._mcp_start_action = IdaCallableAction(
                exec_func=self._mcp_start,
                action_name='mcpyida_start',
                display_name='Start MCP Server',
                menu_path=MENU_PATH,
                update_func=self._mcp_start_update,
            )
            self._mcp_stop_action = IdaCallableAction(
                exec_func=self._mcp_stop,
                action_name='mcpyida_stop',
                display_name='Stop MCP Server',
                menu_path=MENU_PATH,
                update_func=self._mcp_stop_update,
            )

            self._ui_hooks = _UiHooks(
                ui_ready_handler=self._ui_ready_handler, db_init=self._db_init
            )
            self._idb_hooks = _IdbHooks(
                analysis_complete_handler=self._analysis_complete_handler,
                idb_closing_handler=self._idb_closing_handler,
            )

            self._ui_hooks.hook()
            self._idb_hooks.hook()

        def _ui_ready_handler(self) -> None:
            print('Registering MCPyIDA plugin actions')
            self._mcp_start_action.register()
            self._mcp_stop_action.register()

            # Auto-start MCP server if a database is loaded
            if ida_nalt.get_input_file_path():
                self._mcp_start(None)

        def _db_init(self, is_new_db: bool) -> None:
            # Auto-start MCP server when a new database is opened/created
            self._mcp_start(None)

        def _analysis_complete_handler(self) -> None: ...

        def _idb_closing_handler(self) -> None:
            self._mcp_stop(None)

        def _mcp_start(self, ctx: Any) -> int:
            self._mcp_server.start('127.0.0.1')
            return 1

        def _mcp_start_update(self, ctx: Any) -> int:
            if ida_nalt.get_input_file_path():
                return (
                    idaapi.AST_ENABLE
                    if self._mcp_server.state == McpServerState.STOPPED
                    else idaapi.AST_DISABLE
                )
            return idaapi.AST_DISABLE

        def _mcp_stop(self, ctx: Any) -> int:
            self._mcp_server.stop()
            print('MCP Server: Stopped')
            return 1

        def _mcp_stop_update(self, ctx: Any) -> int:
            if ida_nalt.get_input_file_path():
                return (
                    idaapi.AST_ENABLE
                    if self._mcp_server.state == McpServerState.RUNNING
                    else idaapi.AST_DISABLE
                )
            return idaapi.AST_DISABLE

        def run(self, ctx: Any) -> int:  # noqa: ARG002
            # IDA's plugin protocol requires this method to exist; we have
            # no per-action handler beyond what's wired through start/stop.
            return 0

        def __del__(self):
            self._mcp_stop(None)

    class MCPyIdaPlugin(idaapi.plugin_t):  # type: ignore
        """The IDA plugin loader that provides the plugin instance"""

        flags = idaapi.PLUGIN_MULTI
        comment = 'IDA MCP Server'
        help = 'MCP Help'
        wanted_name = 'MCPyIDA'
        wanted_hotkey = ''

        def __init__(self) -> None: ...

        def init(self) -> idaapi.plugmod_t:
            """Initialize the plugin."""

            return MCPyIdaPlugMod()

        def run(self, arg):  # type: ignore
            pass  # Not used with modern plugins

        def term(self):  # type: ignore
            pass  # Not used with modern plugins
