import pefile
from capstone import *

from Grabber.config.sample import Sample


class Disassembler():

    __path: str
    __sample: Sample
    __md: Cs

    def __init__(self, path: str) -> None:
        self.__path = path
        self.__sample = Sample(path)

        with pefile.PE(self.__path) as pe:
            if (pe.FILE_HEADER.Machine == 0x014c):
                self.__md = Cs(CS_ARCH_X86, CS_MODE_32)
            elif (pe.FILE_HEADER.Machine == 0x8664):
                self.__md = Cs(CS_ARCH_X86, CS_MODE_64)
            else:
                raise TypeError("Unknown processor architecrute!")

    def getInstruction(self, address: int) -> str:
        physical_address = self.__sample.getPhysicalAddress(address)

        data = self.__sample.getData()
        data = data[physical_address:physical_address+16]

        try:
            instruction = next(self.__md.disasm(data, address, 1))
        except StopIteration:
            raise ValueError(f"Can't disassemble address {hex(address)}!")

        return instruction.mnemonic + " " + instruction.op_str
