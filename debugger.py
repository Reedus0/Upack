import pefile
import py3dbg
import py3dbg.defines

from capstone import *


class Debugger():

    __dbg: py3dbg.pydbg
    __path: str
    __md: Cs
    __next_address: int
    __cache: set

    def __handleBreak(self, _: py3dbg.pydbg) -> int:
        self.__next_address = self.__dbg.context.Rip

        if (self.__next_address not in self.__cache):
            self.__dbg.single_step(True)
            self.__cache.add(self.__next_address)

        return py3dbg.defines.DBG_EXCEPTION_HANDLED

    def __init__(self, path: str) -> None:
        self.__path = path
        self.__cache = set()

        with pefile.PE(self.__path) as pe:
            self.__next_address = pe.OPTIONAL_HEADER.AddressOfEntryPoint + \
                pe.OPTIONAL_HEADER.ImageBase

            if (pe.FILE_HEADER.Machine == 0x014c):
                self.__md = Cs(CS_ARCH_X86, CS_MODE_32)
            elif (pe.FILE_HEADER.Machine == 0x8664):
                self.__md = Cs(CS_ARCH_X86, CS_MODE_64)
            else:
                raise TypeError("Unknown processor architecrute!")

        self.__dbg = py3dbg.pydbg()
        self.__dbg.load(path.encode())

        self.__dbg.bp_set(self.__next_address)

        self.__dbg.set_callback(
            py3dbg.defines.EXCEPTION_SINGLE_STEP, self.__handleBreak)

    def getNextInstruction(self) -> tuple[str, int]:
        if (not self.__dbg.debugger_active):
            raise Exception("Program has exited!")
        self.__dbg.debug_event_iteration()
        data = self.__dbg.read_process_memory(self.__next_address, 16)

        try:
            instruction = next(self.__md.disasm(data, self.__next_address, 1))
        except StopIteration:
            raise ValueError(
                f"Can't disassemble address {hex(self.__next_address)}!")

        return (instruction.mnemonic + " " + instruction.op_str, self.__next_address)
