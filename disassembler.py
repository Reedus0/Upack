import re
from pefile import PE, SectionStructure
from capstone import *


class Disassembler():

    __path: str
    __md: Cs
    __offset: int
    __data: bytes
    __sections: list[SectionStructure]

    def __init__(self, path: str, aslr_entry: int) -> None:
        self.__path = path

        with PE(self.__path) as pe:
            self.__offset = aslr_entry - \
                (pe.OPTIONAL_HEADER.AddressOfEntryPoint +
                 pe.OPTIONAL_HEADER.ImageBase)
            self.__sections = pe.sections
            self.__image_base = pe.OPTIONAL_HEADER.ImageBase

            if (pe.FILE_HEADER.Machine == 0x014c):
                self.__md = Cs(CS_ARCH_X86, CS_MODE_32)
            elif (pe.FILE_HEADER.Machine == 0x8664):
                self.__md = Cs(CS_ARCH_X86, CS_MODE_64)
            else:
                raise TypeError("Unknown processor architecrute!")

        with open(path, "rb") as file:
            self.__data = file.read()

    def getPhysicalAddress(self, virutal_address: int) -> int:
        for section in self.__sections:

            section_address = section.VirtualAddress
            section_size = section.Misc_VirtualSize

            if (section_address <= virutal_address < section_address + section_size + self.__image_base):
                physical_address = section.PointerToRawData + \
                    (virutal_address - section_address -
                     self.__image_base)
                if (physical_address < 0):
                    physical_address += self.__image_base
                return physical_address
        return 0

    def getInstruction(self, address: int) -> str:
        physical_address = self.getPhysicalAddress(
            address - self.__offset)

        data = self.__data
        data = data[physical_address:physical_address+16]

        try:
            instruction = next(self.__md.disasm(data, address, 1))
        except StopIteration:
            return ("")

        return instruction.mnemonic + " " + instruction.op_str
