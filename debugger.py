import subprocess
import os

import pefile
import ctypes
import py3dbg
import py3dbg.defines

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32


class Debugger():

    __dbg: py3dbg.pydbg
    __path: str
    __md: Cs
    __next_address: int
    __next_instruction: str
    __cache: dict
    __pages: dict
    __wordsize: int

    def __handleBreak(self, _: py3dbg.pydbg) -> int:
        if (self.__wordsize == 32):
            self.__next_address = self.__dbg.context.Eip
        elif (self.__wordsize == 64):
            self.__next_address = self.__dbg.context.Rip

        self.__dbg.bp_del(self.__next_address)

        if (self.__next_address > 0x7F0000000000):
            return py3dbg.defines.DBG_EXCEPTION_HANDLED

        if (self.__wordsize == 32):
            if (self.__next_address > 0x70000000 and self.__next_address < 0x7FFFFFFF):
                return py3dbg.defines.DBG_EXCEPTION_HANDLED

        assert self.__next_address, "Can't read address 0x0!"

        padded_address = self.__next_address & 0xFFFFFFFFFFFFF000

        if (padded_address not in self.__pages):
            data = self.__dbg.read_process_memory(padded_address, 4096)
            self.__pages[padded_address] = data

        instruction_offset = self.__next_address & 0xFFF
        instruction_address = self.__pages[padded_address][instruction_offset:instruction_offset + 16]

        try:
            instruction = next(self.__md.disasm(
                instruction_address, self.__next_address, 1))
            self.__next_instruction = instruction.mnemonic + \
                " " + instruction.op_str
        except StopIteration:
            self.__next_instruction = ""
            return py3dbg.defines.DBG_EXCEPTION_HANDLED

        if (self.__next_instruction[:4] == "call" or self.__next_instruction[0] == "j" or self.__next_instruction[:3] == "rep"):
            self.__dbg.bp_set(self.__next_address + len(instruction.bytes))
            if (self.__next_instruction[:3] != "rep"):
                try:
                    self.__dbg.bp_set(int(instruction.op_str, 16))
                    self.__dbg.bp_set(getattr(self.__dbg.context,
                                              instruction.op_str.capitalize()))
                except Exception:
                    pass

        if (self.__next_address in self.__cache):
            if (self.__cache[self.__next_address] == self.__next_instruction):
                return py3dbg.defines.DBG_EXCEPTION_HANDLED

        self.__cache[self.__next_address] = self.__next_instruction

        self.__dbg.context.EFlags |= py3dbg.defines.EFLAGS_TRAP
        self.__dbg.set_thread_context(self.__dbg.context)

        return py3dbg.defines.DBG_EXCEPTION_HANDLED

    def __init__(self, path: str) -> None:
        self.__path = path
        self.__dbg = py3dbg.pydbg()
        self.__cache = dict()
        self.__pages = dict()

        with pefile.PE(self.__path) as pe:
            if (pe.FILE_HEADER.Machine == 0x014C):
                self.__wordsize = 32
                self.__md = Cs(CS_ARCH_X86, CS_MODE_32)
            elif (pe.FILE_HEADER.Machine == 0x8664):
                self.__wordsize = 64
                self.__md = Cs(CS_ARCH_X86, CS_MODE_64)
            else:
                raise TypeError("Unsupported processor architecrute!")

        self.__dbg.set_callback(
            py3dbg.defines.EXCEPTION_SINGLE_STEP, self.__handleBreak)
        self.__dbg.set_callback(
            py3dbg.defines.EXCEPTION_BREAKPOINT, self.__handleBreak)

        self.__dbg.load(path.encode(), show_window=False)

        self.__next_instruction = ""
        self.__next_address = self.getEntry()
        self.__dbg.bp_set(self.__next_address)

    def dumpPD(self, address: int) -> None:
        full_dump_path = os.environ["DUMP_PATH"] + "/" + str(self.__dbg.pid)

        try:
            os.makedirs(full_dump_path)
        except FileExistsError:
            pass

        subprocess.call(
            f"{os.environ["PD_PATH"]}/pd64.exe -a {address} -pid {self.__dbg.pid} -o {full_dump_path}", stdout=subprocess.DEVNULL)
        subprocess.call(
            f"{os.environ["PD_PATH"]}/pd64.exe -pid {self.__dbg.pid} -o {full_dump_path}", stdout=subprocess.DEVNULL)

    def dumpBinary(self, address: int) -> None:
        full_dump_path = os.environ["DUMP_PATH"] + "/" + str(self.__dbg.pid)

        try:
            os.makedirs(full_dump_path)
        except FileExistsError:
            pass

        assert address, "Can't read address 0x0!"
        data = self.__dbg.read_process_memory(address, 4096)
        with open(full_dump_path + "/" + hex(address), "wb") as file:
            file.write(data)

    def getEntry(self) -> int:
        thread = self.__dbg.enumerate_threads()[0]
        handle = self.__dbg.open_thread(thread)

        dwStartAddress = ctypes.c_size_t()
        ntdll = ctypes.CDLL("ntdll")

        NtQueryInformationThread = ntdll.NtQueryInformationThread

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
            raise ChildProcessError("Program has exited!")

        self.__dbg.debug_event_iteration()

        if (self.__next_address > 0x7F0000000000):
            return self.getNextInstruction()

        if (self.__wordsize == 32):
            if (self.__next_address > 0x70000000 and self.__next_address < 0x7FFFFFFF):
                return self.getNextInstruction()

        return (self.__next_instruction, self.__next_address)
