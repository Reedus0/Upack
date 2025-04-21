import py3dbg
import py3dbg.defines


class Debuger():

    __path: str

    def __init__(self, path: str) -> None:
        self.__path = path
