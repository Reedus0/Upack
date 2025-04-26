import os
import sys

from time import time

from dotenv import load_dotenv
from Grabber.logs.logger import initLogging, log

from disassembler import Disassembler
from debugger import Debugger


def main():

    load_dotenv()
    initLogging(0, os.environ["LOG_PATH"])

    if (len(sys.argv) < 2):
        print(f"Usage: {sys.argv[0]} sample")
        exit(1)

    debugger = Debugger(os.environ["SAMPLE_PATH"] + "/" + sys.argv[1])
    disassembler = Disassembler(os.environ["SAMPLE_PATH"] + "/" + sys.argv[1])

    result = 0

    while (1):
        try:
            mnemonic, next_address = debugger.getNextInstruction()
            # print(
            #     f"{next_address:#0{16}x}: {mnemonic}")
            disassemled_instruction = disassembler.getInstruction(
                next_address)
            if (disassemled_instruction and disassemled_instruction != mnemonic):
                print(
                    f"{next_address:#0{16}x}: {mnemonic:{" "}<40} {disassemled_instruction}")
                result += 1
        except Exception as e:
            log(10, str(e))
            break

    print("result: " + str(result))


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log(30, str(e))
        exit(1)
