import gdb
from pathlib import Path

class Context:
    def __init__(self, filename="input_file",):
        self.filename = filename
        self.f_buff = b""
        self.len_buff = 0
        self.addr = 0
    
    def alloc_memory(self, inf):
        """
        Allocate memory in the targer process using VirtualAlloc
        """
        print("allocating memory")
        IAT_VIRTUALALLOC = 0x4060c8
        va_addr = int.from_bytes(inf.read_memory(IAT_VIRTUALALLOC, 4), "little")
        if va_addr == 0:
            raise gdb.GdbError("Invalid Memory address for kernel32.dll!VirtualAlloc")
        # print(f"Virtual Alloc is at address {va_addr:#x}")
        cmd = f"((void*(*) (void*, unsigned long, unsigned long, unsigned long)){va_addr:#x})(0, {self.len_buff:#x}, 0x3000, 0x40)"
        self.addr = int(gdb.parse_and_eval(cmd))
        if self.addr == 0:
            gdb.GdbError("Failed to allocate a memory block")
            gdb.execute("kill")
        return self.addr
    
    def read_file(self):
        """
        read encoded data from input file
        """
        print("reading file")
        with open(self.filename, "rb") as f:
            self.f_buff = f.read()
        # self.f_buff = b"Hello world!\nThis is my first memory injection script\n"
        self.len_buff = len(self.f_buff)
        print(f"Length read from file: {self.len_buff:#x}")
        return self.f_buff, self.len_buff
    
    def write_to_memory(self, inf, chunk_size=0x10):
        """
        Write data to allocated memory.
        """
        print("writing to memory")
        # print(inf)
        if self.len_buff > chunk_size:
            for offset in range(0,self.len_buff, chunk_size):
                chunk = self.f_buff[offset:offset+chunk_size]
                curr_addr = self.addr + offset
                inf.write_memory(curr_addr, chunk)
                print("*"*5)
        else:
            inf.write_memory(self.addr, self.f_buff)
        print("done writing to memory")
    
    def read_memory(self, inf):
        """
        confirm memory write operation by reading the data at the allocated memory
        """
        print("reading from the allocated memory")
        data = inf.read_memory(self.addr, self.len_buff).tobytes()
        print(f"{data}")

    def change_register_edx(self, frame):
        print("changing register edx")
        edx = int(frame.read_register("edx"))
        print(f"EDX before change: {edx}")
        cmd_edx = f"set $edx = {self.len_buff:#x}"
        gdb.execute(cmd_edx)
        edx = int(frame.read_register("edx"))
        print(f"EDX after change: {edx}")

    def change_register_eax(self, frame):
        print("changing register eax")
        eax = int(frame.read_register("eax"))
        print(f"EAX before change: {eax:#x}")
        cmd_eax = f"set $eax = {self.addr:#x}"
        gdb.execute(cmd_eax)
        eax = int(frame.read_register("eax"))
        print(f"EAX before change: {eax:#x}")

    def rename_files(self):
        for f in Path(".").iterdir():
            if f.is_file and f.name.startswith("temp"):
                Path(f.name).rename(f"{f.name}.bmp")
        
class Breakpoint1(gdb.Breakpoint):
    def __init__(self, location, ctx: Context):
        super(Breakpoint1, self).__init__(location, gdb.BP_BREAKPOINT)
        self.ctx = ctx

    def stop(self):
        print("hit first breakpoint")
        buf,sz = self.ctx.read_file()
        inf = gdb.selected_inferior()
        addr = self.ctx.alloc_memory(inf)
        print(f"Allocated memory is at {addr:#x}")
        gdb.execute("info registers eip", to_string=True)
        self.ctx.write_to_memory(inf)
        # self.ctx.read_memory(inf)
        frame = gdb.selected_frame()
        self.ctx.change_register_edx(frame=frame)
        return False

class Breakpoint2(gdb.Breakpoint):
    def __init__(self, location, ctx: Context):
        super(Breakpoint2, self).__init__(location, gdb.BP_BREAKPOINT)
        self.ctx = ctx

    def stop(self):
        print("hit the second breakpoint")
        frame = gdb.selected_frame()
        self.ctx.change_register_eax(frame=frame)
        return False

class Breakpoint3(gdb.Breakpoint):
    def __init__(self, location, ctx: Context):
        super(Breakpoint3, self).__init__(location, gdb.BP_BREAKPOINT)
        self.ctx = ctx
    
    def stop(self):
        print("hit the third breakpoint")
        self.ctx.rename_files()
        return True
        

if __name__ == "__main__":
    gdb.execute("set pagination off")
    gdb.execute("set confirm off")
    gdb.execute("target remote 127.0.0.1:12346")
    gdb.execute("handle SIGSEGV pass noprint nostop")
    context = Context()
    BP_ADDR = f"*{0x40187b:#x}"
    br1 = Breakpoint1(BP_ADDR, context)
    BP_ADDR2 = f"*{0x40187f:#x}"
    br2 = Breakpoint2(BP_ADDR2, context)
    BP_ADDR3 = f"*{0x4018bd:#x}"
    br3 = Breakpoint3(BP_ADDR3, context)

    gdb.execute("continue")
    print("end of script")

