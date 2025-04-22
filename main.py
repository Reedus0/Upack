import os
import sys

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

    while (1):
        try:
            mnemonic, next_address = debugger.getNextInstruction()
            print(mnemonic)
            print(disassembler.getInstruction(next_address))
            if (disassembler.getInstruction(next_address) != mnemonic):
                print(disassembler.getInstruction(next_address), mnemonic)
        except Exception:
            break

    # debugger.stopDebugger()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log(30, str(e))
        exit(1)
