# Standard Libraries
from typing import (
    cast,
    Dict,
    Optional,
)

# Third Party Libraries
# `idapro` first — see mcpserver.py for rationale.
try:
    import idapro  # noqa: F401  # type: ignore[import-not-found]
except ImportError:
    # idalib's `idapro` exists only in IDA 9.0+ and is only needed for the
    # external-process headless bootstrap.  In the GUI plugin, on IDA 7/8, and
    # in IDA-free environments the kernel is already up (or unused), so its
    # absence is expected and harmless.
    pass
import ida_bytes  # type: ignore[import-not-found]
import ida_funcs  # type: ignore[import-not-found]
import ida_hexrays  # type: ignore[import-not-found]
import ida_lines  # type: ignore[import-not-found]
import ida_typeinf  # type: ignore[import-not-found]
import idaapi  # type: ignore[import-not-found]
import idc  # type: ignore[import-not-found]


from mcpyida.util import is_headless  # noqa: F401 — canonical definition lives in util.py


class IdaException(Exception): ...


class IdaFunctionEditException(IdaException): ...


ExecutableAddress = int


class IdaFunction:
    def __init__(self, address: ExecutableAddress) -> None:
        self._address = address
        self._func = ida_funcs.get_func(address)
        if self._func is None:
            raise ValueError(f'No function found containing address 0x{address:X}')
        self._decompiled: ida_hexrays.cfuncptr_t | None = None
        # Eagerly typed dicts (always present) plus a separate "loaded" flag
        # for lazy-init detection; mypy can't narrow Optional[dict] across
        # method calls, so initializing to {} keeps the types tight.
        self._locals: Dict[str, IdaLocalVariable] = {}
        self._locals_loaded: bool = False
        self._globals: Dict[ExecutableAddress, IdaGlobalVariable] = {}
        self._globals_by_name: Dict[str, IdaGlobalVariable] = {}
        self._globals_loaded: bool = False
        self._labels: Dict[int, IdaUserLabel] = {}
        self._labels_by_name: Dict[str, IdaUserLabel] = {}

        self._vdui: Optional[ida_hexrays.vdui_t] = None
        self._til: ida_typeinf.til_t = idaapi.get_idati()

    def reset_decompile(self) -> None:
        self._decompiled = ida_hexrays.decompile_func(self._func, None)
        if self._decompiled is not None:
            self._decompiled.get_pseudocode()

    def _load_locals(self) -> None:
        # load local variables
        self._locals.clear()
        for index, lvar in enumerate(self.decompiled.get_lvars()):
            self._locals[lvar.name] = IdaLocalVariable(self, index)

    def _load_globals(self) -> None:
        # load globals and labels
        for item in self.decompiled.treeitems:
            if item.label_num > 0:
                label = IdaUserLabel(self, item.label_num)
                self._labels[item.label_num] = label
                self._labels_by_name[label.name] = label
            item_expr = item.cexpr
            try:
                for key, op_item in item_expr.operands.items():
                    if op_item.opname == 'obj' and op_item.obj_ea != idc.BADADDR:
                        item_name = idc.get_name(op_item.obj_ea)
                        global_var = IdaGlobalVariable(self, op_item)
                        self._globals_by_name[op_item.obj_ea] = global_var
                        self._globals_by_name[item_name] = global_var
            except Exception:
                pass

    @property
    def addr(self) -> ExecutableAddress:
        return self._address

    @property
    def end_addr(self) -> ExecutableAddress:
        return self._func.end_ea

    @property
    def signature(self) -> str:
        return idc.get_type(self.addr)

    @property
    def pseudocode(self) -> str:
        return str(self.decompiled)

    @property
    def disasm(self) -> str:
        ea = self._func.start_ea
        result = []
        while ea < self._func.end_ea:
            # Create insn_t object and decode instruction
            insn = idaapi.insn_t()
            if not idaapi.decode_insn(insn, ea):
                insn_size = 0
                insn_bytes = b''
                disasm_line = '<invalid instruction>'
            else:
                insn_size = insn.size
                insn_bytes = ida_bytes.get_bytes(ea, insn_size) or b''

                # Generate disasm line and remove IDA's formatting tags
                disasm_line = ida_lines.generate_disasm_line(ea, 0)
                if disasm_line:
                    disasm_line = ida_lines.tag_remove(disasm_line)
                else:
                    disasm_line = '<invalid instruction>'

            # Format hex bytes
            hex_bytes = ' '.join(f'{b:02X}' for b in insn_bytes)

            # Add comment if exists
            comment = idaapi.get_cmt(ea, False) or ''
            comment_str = f' ; {comment}' if comment else ''

            result.append(f'0x{ea:X}: {hex_bytes:<20} {disasm_line}{comment_str}')

            ea = idaapi.next_head(ea, self._func.end_ea)

        return '\n'.join(result)

    @property
    def decompiled(self) -> ida_hexrays.cfuncptr_t:
        if self._decompiled is None:
            self.reset_decompile()
        if self._decompiled is None:
            raise IdaException(
                f'No decompilation for function {self.name} @ {self.addr:#x}'
            )
        return self._decompiled

    @property
    def comment(self) -> str:
        return str(ida_funcs.get_func_cmt(self._func, False))

    @comment.setter
    def comment(self, comment: str) -> None:
        ida_funcs.set_func_cmt(self._func, comment, False)

    @property
    def name(self) -> str:
        return str(ida_funcs.get_func_name(self._func.start_ea))

    @name.setter
    def name(self, name: str) -> None:
        idaapi.set_name(self._func.start_ea, name, idaapi.SN_FORCE)

    @property
    def demangled_name(self) -> str:
        name = self.name
        demangled = idc.demangle_name(name, idc.DEMNAM_FIRST)
        return demangled if demangled else name

    @property
    def locals(self) -> Dict[str, 'IdaLocalVariable']:
        if not self._locals_loaded:
            self._load_locals()
            self._locals_loaded = True
        return self._locals

    @property
    def globals(self) -> Dict[str, 'IdaGlobalVariable']:
        if not self._globals_loaded:
            self._load_globals()
            self._globals_loaded = True
        return self._globals_by_name

    @property
    def labels(self) -> Dict[str, 'IdaUserLabel']:
        if not self._globals_loaded:
            self._load_globals()
            self._globals_loaded = True
        return self._labels_by_name

    def get_decompiler_view(self) -> ida_hexrays.vdui_t | None:
        if is_headless():
            return None
        if self._vdui is None:
            # open_pseudocode returns vdui_t and creates/finds the Pseudocode window
            self._vdui = ida_hexrays.open_pseudocode(self._func.start_ea, 0)
        return self._vdui

    def set_disassembly_comment(
        self, comment_addr: ExecutableAddress, comment: str, repeatable: bool = False
    ) -> bool:
        return bool(ida_bytes.set_cmt(comment_addr, comment, repeatable))

    def set_pseudocode_comment_line(self, line: int, comment: str) -> int:
        sv = self.decompiled.get_pseudocode()
        line -= 1

        if line < 0 or line >= len(sv):
            raise Exception(f'Line {line} is out of range 1-{len(sv)}')

        ea = idaapi.BADADDR
        check_line = -1

        # Generate alternating search order: 0, +1, -1, +2, -2, ... to search both forward and backward
        max_search_range = 10
        search_offsets = [0]
        for i in range(1, max_search_range + 1):
            search_offsets.extend([i, -i])

        for offset in search_offsets:
            check_line = line + offset
            if check_line < 0 or check_line >= len(sv):
                continue

            # 2) work out if this is in the declaration (header) or the statement area
            is_ctree_line = check_line >= self.decompiled.hdrlines
            line_entry = sv[check_line]

            # 3) map line -> ctree item(s)
            head = ida_hexrays.ctree_item_t()
            item = ida_hexrays.ctree_item_t()
            tail = ida_hexrays.ctree_item_t()

            # try cursor at first non-space column (on the displayed text)
            line_text = line_entry.line
            vis = ida_lines.tag_remove(line_text)
            x = next((i for i, ch in enumerate(vis) if not ch.isspace()), 0)

            ok = (
                self.decompiled.get_line_item(
                    line_text, x, is_ctree_line, head, item, tail
                )
                or self.decompiled.get_line_item(
                    line_text, 0, is_ctree_line, head, item, tail
                )
                or self.decompiled.get_line_item(
                    line_text,
                    len(str(line_text).rstrip()) - 1,
                    is_ctree_line,
                    head,
                    item,
                    tail,
                )
            )
            if not ok:
                # print(f'{check_line} Not OK')
                continue

            ci = item.it or head.it or tail.it
            if ci is None:
                # print('ci is None')
                continue

            ea = ci.ea
            if ea != idaapi.BADADDR:
                break
            # print(f'{check_line} Bad Addr: {ea:#x}')
            continue

        if ea == idaapi.BADADDR:
            # print(f'No valid commentable line')
            return 0

        # 4) attach the comment
        tl = ida_hexrays.treeloc_t()
        tl.ea = ea

        commentSet = False

        # IDA's hexrays comment-placement API has no documented way to target a specific
        # ctree item, so we brute-force it: try each ITP_* type until the comment is not orphaned.
        for itp in (
            idaapi.ITP_EMPTY,
            idaapi.ITP_ARG1,
            idaapi.ITP_ARG64,
            idaapi.ITP_BRACE1,
            idaapi.ITP_ASM,
            idaapi.ITP_ELSE,
            idaapi.ITP_DO,
            idaapi.ITP_SEMI,
            idaapi.ITP_CURLY1,
            idaapi.ITP_CURLY2,
            idaapi.ITP_BRACE2,
            idaapi.ITP_COLON,
            idaapi.ITP_BLOCK1,
            idaapi.ITP_BLOCK2,
        ):
            tl.itp = itp
            self.decompiled.set_user_cmt(tl, comment)
            self.decompiled.save_user_cmts()
            # apparently you have to cast cfunc to a string, to make it update itself
            _ = str(self.decompiled)
            if not self.decompiled.has_orphan_cmts():
                commentSet = True
                self.decompiled.save_user_cmts()
                break
            self.decompiled.del_orphan_cmts()

        if not commentSet:
            # print('not commentSet')
            return 0

        if not is_headless():
            self.decompiled.refresh_func_ctext()  # update open pseudocode views
            pc_widget = self.get_decompiler_view()
            if pc_widget:
                pc_widget.refresh_view(True)
        return check_line + 1

    def set_pseudocode_comment(
        self, comment_addr: ExecutableAddress, comment: str
    ) -> bool:
        # get the line of the decompilation for this address
        eamap = self.decompiled.get_eamap()
        decompObjAddr = eamap[comment_addr][0].ea

        # get a ctree location object to place a comment there
        tl = idaapi.treeloc_t()
        tl.ea = decompObjAddr

        commentSet = False
        # IDA's hexrays comment-placement API has no documented way to target a specific
        # ctree item, so we brute-force it: try each ITP_* type until the comment is not orphaned.
        for itp in range(idaapi.ITP_SEMI, idaapi.ITP_COLON):
            tl.itp = itp
            self.decompiled.set_user_cmt(tl, comment)
            self.decompiled.save_user_cmts()
            # apparently you have to cast cfunc to a string, to make it update itself
            _ = str(self.decompiled)
            if not self.decompiled.has_orphan_cmts():
                commentSet = True
                self.decompiled.save_user_cmts()
                break
            self.decompiled.del_orphan_cmts()

        if not commentSet:
            return False

        if not is_headless():
            pc_widget = self.get_decompiler_view()
            if pc_widget:
                pc_widget.refresh_view(True)

        return True


class IdaLocalVariable:
    def __init__(self, parent: IdaFunction, index: int) -> None:
        self._parent: IdaFunction = parent
        self._index = index

    @property
    def lvar(self) -> ida_hexrays.lvar_t:
        return self._parent.decompiled.lvars[self._index]

    @property
    def is_argument(self) -> bool:
        return cast(bool, self.lvar.is_arg_var)

    @property
    def name(self) -> str:
        return str(self.lvar.name)

    @name.setter
    def name(self, name: str) -> None:
        # Use modify_user_lvars for persistent name changes
        # This is the recommended non-GUI approach that avoids INTERR issues
        old_name = self.name
        target_lvar = self.lvar

        class LvarNameModifier(ida_hexrays.user_lvar_modifier_t):
            def __init__(
                self, var_name: str, lvar: 'ida_hexrays.lvar_t', new_name: str
            ):
                ida_hexrays.user_lvar_modifier_t.__init__(self)
                self.var_name = var_name
                self.lvar = lvar
                self.new_name = new_name
                self.modified = False

            def modify_lvars(self, lvars: 'ida_hexrays.lvar_uservec_t') -> bool:
                # Try to find existing entry by name or location
                for lvar_info in lvars.lvvec:
                    # Match by name if set, or by location
                    if (
                        lvar_info.name == self.var_name
                        or lvar_info.ll.location == self.lvar.location
                    ):
                        lvar_info.name = self.new_name
                        self.modified = True
                        return True

                # If not found, create a new entry with full locator info
                new_info = ida_hexrays.lvar_saved_info_t()
                new_info.name = self.new_name
                # Set the locator (ll) to identify this variable
                new_info.ll = ida_hexrays.lvar_locator_t()
                new_info.ll.location = self.lvar.location
                new_info.ll.defea = self.lvar.defea
                lvars.lvvec.push_back(new_info)
                self.modified = True
                return True

        modifier = LvarNameModifier(old_name, target_lvar, name)
        ida_hexrays.modify_user_lvars(self._parent.addr, modifier)

        if not modifier.modified:
            raise IdaFunctionEditException(
                f'Failed to rename variable {old_name} to {name}: '
                f'modify_user_lvars did not modify the variable. Check that "{name}" is a valid C identifier, '
                f'not already in use, and not a reserved keyword.'
            )

        # Force redecompilation to apply changes
        self._parent._decompiled = None
        self._parent._vdui = None
        self._parent.reset_decompile()

        # Update locals dictionary
        self._parent.locals.pop(old_name)
        self._parent.locals[name] = self

    @property
    def comment(self) -> str:
        return str(self.lvar.cmt)

    @comment.setter
    def comment(self, comment: str) -> None:
        # Use modify_user_lvars for persistent comment changes
        # This is the recommended non-GUI approach that avoids INTERR issues
        target_name = self.name
        target_lvar = self.lvar

        class LvarCommentModifier(ida_hexrays.user_lvar_modifier_t):
            def __init__(
                self, var_name: str, lvar: 'ida_hexrays.lvar_t', new_comment: str
            ):
                ida_hexrays.user_lvar_modifier_t.__init__(self)
                self.var_name = var_name
                self.lvar = lvar
                self.new_comment = new_comment
                self.modified = False

            def modify_lvars(self, lvars: 'ida_hexrays.lvar_uservec_t') -> bool:
                # Try to find existing entry by name or location
                for lvar_info in lvars.lvvec:
                    # Match by name if set, or by location
                    if (
                        lvar_info.name == self.var_name
                        or lvar_info.ll.location == self.lvar.location
                    ):
                        lvar_info.cmt = self.new_comment
                        self.modified = True
                        return True

                # If not found, create a new entry with full locator info
                new_info = ida_hexrays.lvar_saved_info_t()
                new_info.name = self.var_name
                new_info.cmt = self.new_comment
                # Set the locator (ll) to identify this variable
                new_info.ll = ida_hexrays.lvar_locator_t()
                new_info.ll.location = self.lvar.location
                new_info.ll.defea = self.lvar.defea
                lvars.lvvec.push_back(new_info)
                self.modified = True
                return True

        modifier = LvarCommentModifier(target_name, target_lvar, comment)
        ida_hexrays.modify_user_lvars(self._parent.addr, modifier)

        if not modifier.modified:
            raise IdaFunctionEditException(
                f'Failed to set comment for variable {target_name}: '
                f'modify_user_lvars did not modify the variable.'
            )

        # Force redecompilation to apply changes
        self._parent._decompiled = None
        self._parent._vdui = None
        self._parent.reset_decompile()

    @property
    def type(self) -> str:
        return str(self.lvar.tif)

    @type.setter
    def type(self, type_name: str) -> None:
        type_inf = ida_typeinf.tinfo_t()
        # Use parse_decl for compatibility with both IDA 8 and IDA 9
        # parse_decl returns the remainder of the string after parsing
        # None = total failure, empty string = success (nothing left to parse)
        result = ida_typeinf.parse_decl(type_inf, self._parent._til, f'{type_name};', 0)
        if result is None or not type_inf.is_correct():
            raise IdaFunctionEditException(
                f'Failed to parse type declaration: {type_name}'
            )

        # Note: we intentionally do NOT check if sizes match. IDA's
        # modify_user_lvars / set_lvar_type handles size-mismatched type
        # changes (e.g., int -> SomeStruct*) by re-analyzing the function.
        # A strict size check would block legitimate operations like changing
        # a local int to a struct pointer (4 bytes -> 8 bytes on x64).

        # Use modify_user_lvars for persistent type changes
        # This is the recommended non-GUI approach that avoids INTERR issues
        # See: https://github.com/TakahiroHaruyama/VDR/blob/main/ida_ioctl_propagate.py
        target_name = self.name
        target_lvar = self.lvar

        class LvarTypeModifier(ida_hexrays.user_lvar_modifier_t):
            def __init__(
                self,
                var_name: str,
                lvar: 'ida_hexrays.lvar_t',
                new_type: 'ida_typeinf.tinfo_t',
            ):
                ida_hexrays.user_lvar_modifier_t.__init__(self)
                self.var_name = var_name
                self.lvar = lvar
                self.new_type = new_type
                self.modified = False

            def modify_lvars(self, lvars: 'ida_hexrays.lvar_uservec_t') -> bool:
                # Try to find existing entry by name or location
                for lvar_info in lvars.lvvec:
                    # Match by name if set, or by location
                    if (
                        lvar_info.name == self.var_name
                        or lvar_info.ll.location == self.lvar.location
                    ):
                        lvar_info.type = self.new_type
                        self.modified = True
                        return True

                # If not found, create a new entry with full locator info
                new_info = ida_hexrays.lvar_saved_info_t()
                new_info.name = self.var_name
                new_info.type = self.new_type
                # Set the locator (ll) to identify this variable
                new_info.ll = ida_hexrays.lvar_locator_t()
                new_info.ll.location = self.lvar.location
                new_info.ll.defea = self.lvar.defea
                lvars.lvvec.push_back(new_info)
                self.modified = True
                return True

        modifier = LvarTypeModifier(target_name, target_lvar, type_inf)
        ida_hexrays.modify_user_lvars(self._parent.addr, modifier)

        # Force redecompilation to apply changes
        self._parent._decompiled = None
        self._parent._vdui = None
        self._parent.reset_decompile()

    @property
    def size(self) -> int:
        return cast(int, self.lvar.width)

    @property
    def is_stack_var(self) -> bool:
        return cast(bool, self.lvar.is_stk_var())

    @property
    def is_reg_var(self) -> bool:
        return cast(bool, self.lvar.is_reg_var())

    @property
    def stack_offset(self) -> Optional[int]:
        return self.lvar.get_stkoff() if self.lvar.is_stk_var() else None

    @property
    def reg1(self) -> Optional[int]:
        return self.lvar.get_reg1() if self.lvar.is_reg1() else None

    @property
    def reg2(self) -> Optional[int]:
        return self.lvar.get_reg2() if self.lvar.is_reg2() else None


class IdaGlobalVariable:
    def __init__(self, parent: IdaFunction, expr: ida_hexrays.cexpr_t) -> None:
        self._parent = parent
        self._addr = ExecutableAddress(expr.obj_ea)
        self._type = str(expr.type)
        self._size = int(expr.type.get_unpadded_size())

    @property
    def address(self) -> ExecutableAddress:
        return self._addr

    @property
    def name(self) -> str:
        return str(idc.get_name(self._addr))

    @name.setter
    def name(self, name: str) -> None:
        old_name = self.name
        idc.set_name(self._addr, name)
        self._parent.globals.pop(old_name)
        self._parent.globals[name] = self

    @property
    def comment(self) -> str:
        return str(idc.get_cmt(self._addr, False))

    @comment.setter
    def comment(self, comment: str) -> None:
        idc.set_cmt(self._addr, comment, False)

    @property
    def type(self) -> str:
        return self._type

    @property
    def size(self) -> int:
        return self._size


class IdaUserLabel:
    def __init__(self, parent: IdaFunction, index: int) -> None:
        self._parent = parent
        self._index = index

    @property
    def name(self) -> str:
        lbl: ida_hexrays.citem_t = self._parent.decompiled.find_label(self._index)
        if lbl is None:
            raise IndexError(f'Cannot find label {self._index}')
        userlabel_iter = ida_hexrays.user_labels_find(
            self._parent.decompiled.user_labels, self._index
        )
        if userlabel_iter != ida_hexrays.user_labels_end(
            self._parent.decompiled.user_labels
        ):
            return str(ida_hexrays.user_labels_second(userlabel_iter))
        return f'LABEL_{self._index}'

    @name.setter
    def name(self, name: str) -> None:
        lbl: ida_hexrays.citem_t = self._parent.decompiled.find_label(self._index)
        if lbl is None:
            raise IndexError(f'Cannot find label {self._index}')
        user_labels_map = self._parent.decompiled.user_labels
        userlabel_iter = ida_hexrays.user_labels_find(user_labels_map, self._index)
        while userlabel_iter != ida_hexrays.user_labels_end(user_labels_map):
            ida_hexrays.user_labels_erase(user_labels_map, userlabel_iter)
            userlabel_iter = ida_hexrays.user_labels_find(user_labels_map, self._index)
        ida_hexrays.user_labels_insert(user_labels_map, self._index, name)
        self._parent.decompiled.save_user_labels()
        idc.set_name(lbl.ea, name, idaapi.SN_FORCE)

    @property
    def address_name(self) -> str:
        lbl: ida_hexrays.citem_t = self._parent.decompiled.find_label(self._index)
        if lbl is None:
            raise IndexError(f'Cannot find label {self._index}')
        return str(idc.get_name(lbl.ea))

    @address_name.setter
    def address_name(self, name: str) -> None:
        lbl: ida_hexrays.citem_t = self._parent.decompiled.find_label(self._index)
        if lbl is None:
            raise IndexError(f'Cannot find label {self._index}')
        idc.set_name(lbl.ea, name, idaapi.SN_FORCE)

    @property
    def address(self) -> ExecutableAddress:
        lbl: ida_hexrays.citem_t = self._parent.decompiled.find_label(self._index)
        if lbl is None:
            raise IndexError(f'Cannot find label {self._index}')
        return ExecutableAddress(lbl.ea)

    @property
    def index(self) -> int:
        return self._index
