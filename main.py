import os
import time
import re
import argparse

from dotenv import load_dotenv

from disassembler import Disassembler
from debugger import Debugger


def compare(first, second):
    if (first == second):
        return True

    number_regex = r".*\[?(0x[\dabcdef]{1,8})\]?.*"

    first_match = re.search(number_regex, first)
    second_match = re.search(number_regex, second)

    if (not first_match or not second_match):
        return False

    first_number = int(first_match[1], 16)
    second_number = int(second_match[1], 16)

    return first_number & 0xFFF == second_number & 0xFFF


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument("sample", type=str, help="Sample name")
    parser.add_argument("--all", type=str, help="Print all instructions",
                        action=argparse.BooleanOptionalAction)
    parser.add_argument("--pd", help="Enable memroy pd64 dump",
                        action=argparse.BooleanOptionalAction)
    parser.add_argument("--dump", help="Enable binary dump",
                        action=argparse.BooleanOptionalAction)

    args = parser.parse_args()

    load_dotenv()

    debugger = Debugger(os.environ["SAMPLE_PATH"] + "/" + args.sample)
    disassembler = Disassembler(
        os.environ["SAMPLE_PATH"] + "/" + args.sample, debugger.getEntry())

    result = 0
    start_time = time.time()
    dumped = []

    while (1):
        try:
            mnemonic, next_address = debugger.getNextInstruction()
            disassemled_instruction = disassembler.getInstruction(
                next_address)
            if (args.all):
                print(
                    f"{next_address:#0{16}x}: {mnemonic:{" "}<40}")
            if (mnemonic and disassemled_instruction and not compare(disassemled_instruction, mnemonic)):
                padded_address = next_address & 0xFFFFFFFFFFFFF000
                if (padded_address not in dumped):
                    if (args.pd):
                        debugger.dumpPD(padded_address)
                    if (args.dump):
                        debugger.dumpBinary(padded_address)
                    dumped.append(padded_address)

                print(
                    f"{next_address:#0{16}x}: {mnemonic:{" "}<40} {disassemled_instruction}")
                result += 1
        except ChildProcessError as e:
            print(str(e))
            break

    print(f"time: {time.time() - start_time}, unpacked: {result}")


if __name__ == "__main__":
    main()
