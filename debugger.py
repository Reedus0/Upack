import pefile
import ctypes
import py3dbg
import py3dbg.defines

from capstone import *


class Debugger():

    __dbg: py3dbg.pydbg
    __path: str
    __md: Cs
    __next_address: int
    __cache: dict

    def __handleBreak(self, _: py3dbg.pydbg) -> int:
        self.__next_address = self.__dbg.context.Rip
        self.__dbg.bp_del(self.__next_address)

        if (self.__next_address > 0x7F0000000000):
            return py3dbg.defines.DBG_EXCEPTION_HANDLED

        data = self.__dbg.read_process_memory(self.__next_address, 16)

        try:
            instruction = next(self.__md.disasm(data, self.__next_address, 1))
        except StopIteration:
            raise ValueError(
                f"Can't disassemble address {hex(self.__next_address)}!")

        # print(
        #     f"in {self.__next_address:#0{16}x}: {instruction.mnemonic + " " + instruction.op_str}")

        if (instruction.mnemonic == "call" or instruction.mnemonic[0] == "j" or instruction.mnemonic[:3] == "rep"):
            self.__dbg.bp_set(self.__next_address + len(instruction.bytes))
            if (instruction.mnemonic[:3] != "rep"):
                try:
                    self.__dbg.bp_set(int(instruction.op_str, 16))
                    self.__dbg.bp_set(getattr(self.__dbg.context,
                                              instruction.op_str.capitalize()))
                except Exception:
                    pass

        if (self.__next_address in self.__cache.keys()):
            if (self.__cache[self.__next_address] == instruction.mnemonic + " " + instruction.op_str):
                return py3dbg.defines.DBG_EXCEPTION_HANDLED

        self.__cache[self.__next_address] = instruction.mnemonic + \
            " " + instruction.op_str

        self.__dbg.context.EFlags |= py3dbg.defines.EFLAGS_TRAP
        self.__dbg.set_thread_context(self.__dbg.context)

        return py3dbg.defines.DBG_EXCEPTION_HANDLED

    def __init__(self, path: str) -> None:
        self.__path = path
        self.__dbg = py3dbg.pydbg()
        self.__cache = dict()

        self.__dbg.set_callback(
            py3dbg.defines.EXCEPTION_SINGLE_STEP, self.__handleBreak)
        self.__dbg.set_callback(
            py3dbg.defines.EXCEPTION_BREAKPOINT, self.__handleBreak)

        self.__dbg.load(path.encode(), show_window=True)

        self.__next_address = self.getEntry()
        self.__dbg.bp_set(self.__next_address)

        with pefile.PE(self.__path) as pe:
            if (pe.FILE_HEADER.Machine == 0x014c):
                self.__md = Cs(CS_ARCH_X86, CS_MODE_32)
            elif (pe.FILE_HEADER.Machine == 0x8664):
                self.__md = Cs(CS_ARCH_X86, CS_MODE_64)
            else:
                raise TypeError("Unsupported processor architecrute!")

    def getEntry(self) -> int:
        thread = self.__dbg.enumerate_threads()[0]
        handle = self.__dbg.open_thread(thread)

        ntdll = ctypes.CDLL("ntdll")

        NtQueryInformationThread = ntdll.NtQueryInformationThread

        dwStartAddress = ctypes.c_uint64()
        NtQueryInformationThread(
            handle,
            9,
            ctypes.byref(dwStartAddress),
            ctypes.sizeof(dwStartAddress),
            None
        )

        return dwStartAddress.value

    def getNextInstruction(self) -> tuple[str, int]:
        if (not self.__dbg.debugger_active):
            raise Exception("Program has exited!")

        self.__dbg.debug_event_iteration()

        try:
            data = self.__dbg.read_process_memory(self.__next_address, 16)
        except Exception:
            return ("", self.__next_address)

        try:
            instruction = next(self.__md.disasm(data, self.__next_address, 1))
        except StopIteration:
            raise ValueError(
                f"Can't disassemble address {hex(self.__next_address)}!")

        return (instruction.mnemonic + " " + instruction.op_str, self.__next_address)
