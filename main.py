import os
import sys
import re

from dotenv import load_dotenv
from Grabber.logs.logger import initLogging, log

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

    load_dotenv()
    initLogging(0, os.environ["LOG_PATH"])

    if (len(sys.argv) < 2):
        print(f"Usage: {sys.argv[0]} sample")
        exit(1)

    debugger = Debugger(os.environ["SAMPLE_PATH"] + "/" + sys.argv[1])
    disassembler = Disassembler(
        os.environ["SAMPLE_PATH"] + "/" + sys.argv[1], debugger.getEntry())

    result = 0
    dumped = []

    while (1):
        try:
            mnemonic, next_address = debugger.getNextInstruction()
            disassemled_instruction = disassembler.getInstruction(
                next_address)
            # print(
            #     f"{next_address:#0{16}x}: {mnemonic:{" "}<40}")
            if (disassemled_instruction and not compare(disassemled_instruction, mnemonic)):
                padded_address = next_address & 0xFFFFFFFFFFFFF000
                if (padded_address not in dumped):
                    debugger.dumpProcess(padded_address)
                    dumped.append(padded_address)
                print(
                    f"{next_address:#0{16}x}: {mnemonic:{" "}<40} {disassemled_instruction}")
                result += 1
        except ChildProcessError as e:
            log(10, str(e))
            break

    print("result: " + str(result))


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log(30, str(e))
        exit(1)
