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
        #sel = []
        #for i in xrange(len(ctx.chooser_selection)):
        #    sel.append(str(ctx.chooser_selection.at(i)))
        #print "command %s selected @ %s" % (self.thing, ", ".join(sel))
        pass

    def update(self, ctx):
        return idaapi.AST_ENABLE_FOR_FORM if idaapi.is_chooser_tform(ctx.form_type) else idaapi.AST_DISABLE_FOR_FORM


class MyChoose2(Choose2):

    def __init__(self, title, nb = 5, flags=0, width=None, height=None, embedded=False, modal=False):
        Choose2.__init__(
            self,
            title,
            [ ["Address", 16], ["T", 2], ["Instruction/Data", 60], ["Comment", 100]],
            flags = flags,
            width = width,
            height = height,
            embedded = embedded)
        self.n = 0
        self.items = self.get_all_comments() #[ self.make_item() for x in xrange(0, nb+1) ]
        self.icon = 5
        self.selcount = 0
        self.modal = modal
        self.popup_names = [] #["Inzert", "Del leet", "Ehdeet", "Ree frech"]

        #print("created %s" % str(self))

    def OnClose(self):
        print "closed", str(self)

    def OnEditLine(self, n):
        self.items[n][1] = self.items[n][1] + "*"
        #print("editing %d" % n)

    def OnInsertLine(self):
        self.items.append(self.make_item())
        #print("insert line")

    def OnSelectLine(self, n):
        self.selcount += 1

        ea = int(self.items[n][0], 16)
        idc.jumpto(ea)
        #Warning("[%02d] selectline '%s'" % (self.selcount, n))

    def OnGetLine(self, n):
        #print("getline %d" % n)
        return self.items[n]

    def OnGetSize(self):
        n = len(self.items)
        #print("getsize -> %d" % n)
        return n

    def OnDeleteLine(self, n):
        #print("del %d " % n)
        del self.items[n]
        return n

    def OnRefresh(self, n):
        #print("refresh %d" % n)
        return n

    def OnGetIcon(self, n):
        r = self.items[n]
        t = self.icon + r[1].count("*")
        #print "geticon", n, t
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

    def get_all_comments(self):
        cmts = []
        for seg in idautils.Segments():
            print 'Anylising:', idc.SegName(seg), hex(idc.SegStart(seg)), hex(idc.SegEnd(seg)) + '\n'
            ea = idc.SegStart(seg)
            start = idc.SegStart(seg)
            end = idc.SegEnd(seg)
            while ea < end:

                if ea != idc.BADADDR:
                    cmt = idc.GetCommentEx(ea, True)
                    if cmt:
                        if self.check_isin_filter(cmt):
                            print " Address: ",format(ea, '#16X'),'In fliter,IGN:', cmt
                        else:
                            current_cmt = [format(ea, '#16X'), 'R', idc.GetDisasm(ea), cmt]
                            cmts.append(current_cmt)
                            self.n += 1
                            print " Address: ", format(ea, '#16X'), 'R', 'Comment:', cmt

                    cmt2 = idc.GetCommentEx(ea, False)
                    if cmt2:
                        if self.check_isin_filter(cmt2):
                            print " Address: ",format(ea, '#16X'),'In fliter,IGN:', cmt2
                        else:
                            current_cmt = [format(ea, '#16X'), 'N', idc.GetDisasm(ea), cmt2]
                            cmts.append(current_cmt)
                            self.n += 1
                            print " Address: ",format(ea, '#16X'), 'N', 'Comment:', cmt2
                ea = idc.next_head(ea, end)
        return cmts


    def OnGetLineAttr(self, n):
        pass
        #print("getlineattr %d" % n)
        #if n == 1:
        #    return [0xFF0000, 0]


 # -----------------------------------------------------------------------
def test_choose2(modal=False):
    global c
    c = MyChoose2("Comments List", nb=10, modal=modal)
    r = c.show()
    #c.get_all_comments() # get all comments
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
    wanted_name = "Comments Viewer by obaby"
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
        print "Finished,have a good time"



    def term(self):
        ida_kernwin.hide_wait_box('Analyzing comments in progress, this will take a while.')





def PLUGIN_ENTRY():
    return show_cmts_plugin_t()