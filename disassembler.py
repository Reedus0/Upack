import re
import pefile
from capstone import *

from Grabber.config.sample import Sample


class Disassembler():

    __path: str
    __sample: Sample
    __md: Cs
    __offset: int

    def __init__(self, path: str, aslr_entry: int) -> None:
        self.__path = path
        self.__sample = Sample(path)

        with pefile.PE(self.__path) as pe:
            self.__offset = aslr_entry - \
                (pe.OPTIONAL_HEADER.AddressOfEntryPoint +
                 pe.OPTIONAL_HEADER.ImageBase)

            if (pe.FILE_HEADER.Machine == 0x014c):
                self.__md = Cs(CS_ARCH_X86, CS_MODE_32)
            elif (pe.FILE_HEADER.Machine == 0x8664):
                self.__md = Cs(CS_ARCH_X86, CS_MODE_64)
            else:
                raise TypeError("Unknown processor architecrute!")

    def getInstruction(self, address: int) -> str:
        physical_address = self.__sample.getPhysicalAddress(
            address - self.__offset)

        data = self.__sample.getData()
        data = data[physical_address:physical_address+16]

        try:
            instruction = next(self.__md.disasm(data, address, 1))
        except StopIteration:
            return ("")

        return instruction.mnemonic + " " + instruction.op_str
