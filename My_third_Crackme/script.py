import gdb

class Breakpoint1(gdb.Breakpoint):
    def __init__(self, location):
        super(Breakpoint1, self).__init__(location, gdb.BP_BREAKPOINT)

    def stop(self):
        print("first breakpoint hit")
        return False

class Breakpoint2(gdb.Breakpoint):
    def __init__(self, location):
        super(Breakpoint2, self).__init__(location, gdb.BP_BREAKPOINT)
    
    def stop(self):
        """Change register RAX value in IsDebuggerPresent"""
        print("changing register RAX value")
        frame = gdb.selected_frame()
        rax = int(frame.read_register("rax"))
        print(f"RAX before change {rax:#x}")
        gdb.execute("set $rax=0x0")
        rax = int(frame.read_register("rax"))
        print(f"RAX after change {rax:#x}")
        return False

class Breakpoint3(gdb.Breakpoint):
    def __init__(self, location):
        super(Breakpoint3, self).__init__(location, gdb.BP_BREAKPOINT)
    
    def stop(self):
        """
        Change ZF register value at 0x140001539
        """
        print("Changing ZF value")
        frame = gdb.selected_frame()
        gdb.execute("set $eflags |= 0x40")
        return False

class Breakpoint5(gdb.Breakpoint):
    def __init__(self, location):
        super(Breakpoint5, self).__init__(location, gdb.BP_BREAKPOINT)
    
    def stop(self):
        """
        ensure password entred is 16 characters long
        """
        print("changing register EAX")
        gdb.execute("set $rax=0x11")
        frame = gdb.selected_frame()
        rax = int(frame.read_register("rax"))
        print(f"Register RAX value: {rax:#x}")
        return False


def setup():
    gdb.execute("set pagination off")
    gdb.execute("set confirm off")
    gdb.execute("set architecture i386:x86-64")
    gdb.execute("handle SIGSEGV noprint nostop pass")
    gdb.execute("set auto-solib-add off")
    gdb.execute("target remote 127.0.0.1:12345")
    

if __name__ == "__main__":
    setup()
    BP_ADDR = f"*{0x140001440:#x}"
    br1 = Breakpoint1(BP_ADDR)
    BP_ADDR2 = f"*{0x1400014ce:#x}"
    br2 = Breakpoint2(BP_ADDR2)
    BP_ADDR3 = f"*{0x140001539:#x}"
    br3 = Breakpoint3(BP_ADDR3)
    # BP_ADDR4 = f"*{0x140001622:#x}"
    # br4 = Breakpoint4(BP_ADDR4)
    BP_ADDR5 = f"*{0x1400014bc:#x}"
    br5 = Breakpoint5(BP_ADDR5)
    gdb.execute("continue")
