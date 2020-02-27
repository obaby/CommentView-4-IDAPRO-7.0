'''
 '----------------------------------------------------------------------------------------------------------'
 'IDA Comments Viewer for IDA pro 7.0'
 'Version:1.0 alpha'
 'plugin by obaby'
 'http://www.h4ck.org.cn http://findu.co'
 '----------------------------------------------------------------------------------------------------------'
'''


import idaapi
from ida_ida import *
import idautils
import idc
from idaapi import Choose2
import ida_kernwin


class chooser_handler_t(idaapi.action_handler_t):
    def __init__(self, thing):
        idaapi.action_handler_t.__init__(self)
        self.thing = thing

    def activate(self, ctx):
        pass

    def update(self, ctx):
        return idaapi.AST_ENABLE_FOR_FORM if idaapi.is_chooser_tform(ctx.form_type) else idaapi.AST_DISABLE_FOR_FORM


class MyChoose2(Choose2):
    def __init__(self, title, nb = 5, flags=0, width=None, height=None, embedded=False, modal=False):
        Choose2.__init__(
            self,
            title,
            [ ["Address", 20], ["Type", 2], ["Instruction/Data", 24], ["Comment", 36]],
            flags = flags,
            width = width,
            height = height,
            embedded = embedded)
        self.n = 0
        self.items = self.get_asm_comments() + self.get_f5_comments()
        self.icon = 5
        self.selcount = 0
        self.modal = modal
        self.popup_names = []   # ["Insert", "Delete", "Edit", "Refresh"]

    def OnClose(self):
        print "closed", str(self)

    def OnEditLine(self, n):
        self.items[n][1] = self.items[n][1] + "*"

    def OnInsertLine(self):
        self.items.append(self.make_item())

    def OnSelectLine(self, n):
        self.selcount += 1
        ea = int(self.items[n][0].split(":")[1], 16)
        idc.jumpto(ea)

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        n = len(self.items)
        return n

    def OnDeleteLine(self, n):
        del self.items[n]
        return n

    def OnRefresh(self, n):
        return n

    def OnGetIcon(self, n):
        r = self.items[n]
        t = self.icon + r[1].count("*")
        return t

    def show(self):
        return self.Show(self.modal) >= 0

    def make_item(self):
        r = [str(self.n), "func_%04d" % self.n]
        self.n += 1
        return r

    def check_isin_filter(self, cmt):
        cmt_str = str(cmt)
        if cmt_str.startswith('void') or cmt_str.startswith('char') \
                or cmt_str.startswith('int') or cmt_str.startswith('switch') \
                or cmt_str.startswith('jump') or cmt_str.startswith('size_t') \
                or cmt_str.startswith('dw') or cmt_str.startswith('nSize') \
                or cmt_str.startswith('hFile') or cmt_str.startswith('lp'):
            return True
        else:
            return False

    def get_asm_comments(self):
        cmts = []
        for seg in idautils.Segments():
            seg_name = idc.SegName(seg)
            ea = idc.SegStart(seg)
            end = idc.SegEnd(seg)
            while ea < end:
                if ea != idc.BADADDR:
                    cmt = idc.GetCommentEx(ea, True)    # repeatable comments
                    if cmt:
                        if not self.check_isin_filter(cmt):
                            current_cmt = ["%s:%-16X" % (seg_name, ea), 'R', idc.GetDisasm(ea), cmt]
                            cmts.append(current_cmt)
                            self.n += 1

                    cmt2 = idc.GetCommentEx(ea, False)  # usual comments
                    if cmt2:
                        if not self.check_isin_filter(cmt2):
                            current_cmt = ["%s:%-16X" % (seg_name, ea), 'N', idc.GetDisasm(ea), cmt2]
                            cmts.append(current_cmt)
                            self.n += 1
                ea = idc.next_head(ea, end)
        return cmts

    def get_f5_comments(self):
        cmts = []
        for seg in idautils.Segments():
            ea = idc.SegStart(seg)
            if idc.GetSegmentAttr(ea, idc.SEGATTR_TYPE) != idaapi.SEG_CODE:
                continue

            seg_name = idc.SegName(seg)
            end = idc.SegEnd(seg)
            while ea < end:
                if ea != idc.BADADDR and idc.GetFunctionFlags(ea) != 0xffffffff:
                    try:
                        cfunc = idaapi.decompile(ea)
                        for tl, citem in cfunc.user_cmts.items():
                            current_cmt = ["%s:%-16X" % (seg_name, tl.ea), 'F5', idc.GetDisasm(tl.ea), citem.c_str()]   # F5 comments
                            cmts.append(current_cmt)
                            self.n += 1
                    except idaapi.DecompilationFailure:
                        pass
                    finally:
                        ea = idc.GetFunctionAttr(ea, idc.FUNCATTR_END)
                else:
                    ea = idc.next_head(ea, end)
        return cmts

    def OnGetLineAttr(self, n):
        pass

 # -----------------------------------------------------------------------
def test_choose2(modal=False):
    global c
    c = MyChoose2("Comments List", nb=10, modal=modal)
    r = c.show()
    form = idaapi.get_current_tform()
    for thing in ["A", "B"]:
        idaapi.attach_action_to_popup(form, None, "choose2:act%s" % thing)


# -----------------------------------------------------------------------
def test_choose2_embedded():
    global c
    c = MyChoose2("Comments List", nb=12, embedded=True, width=123, height=222)
    r = c.Embedded()
    if r == 1:
        try:
            if test_embedded:
                o, sel = _idaapi.choose2_get_embedded(c)
                print("o=%s, type(o)=%s" % (str(o), type(o)))
                test_embedded(o)
        finally:
            c.Close()


class show_cmts_plugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "IDA Comments Viewer: generate all comments of the idb"
    help = "Bugs and report: http://www.h4ck.org.cn"
    wanted_name = "Comments Viewer"
    wanted_hotkey = "Ctr-Alt-F8"

    def init(self):
        print '----------------------------------------------------------------------------------------------------------'
        print 'IDA Comments Viewer for IDA pro 7.0'
        print 'Version:1.0 alpha'
        print 'plugin by obaby'
        print 'http://www.h4ck.org.cn http://findu.co'
        print '----------------------------------------------------------------------------------------------------------'
        return idaapi.PLUGIN_OK

    def run(self, arg):
        print "Start to analyzing all comments in idb..."
        ida_kernwin.show_wait_box('Analyzing comments in progress, this will take a while.')
        test_choose2(False)
        ida_kernwin.hide_wait_box('Analyzing comments in progress, this will take a while.')
        print "Finished, have a good time!"

    def term(self):
        ida_kernwin.hide_wait_box('Analyzing comments in progress, this will take a while.')

def PLUGIN_ENTRY():
    return show_cmts_plugin_t()
