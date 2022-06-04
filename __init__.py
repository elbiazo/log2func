from .log2func import log2func
from binaryninja import PluginCommand, log_info
from binaryninja.interaction import get_text_line_input, get_int_input


def binja_log2func(bv):
    func_name = get_text_line_input("Enter function name: ", "Get Func Name")
    func_index = get_int_input("Enter function index: ", "Get Func Index")

    output = log2func(bv, func_name.decode(), func_index)
    for addr in output.keys():
        log_info(f"{hex(addr)} -> {output[addr]}")
        bv.get_function_at(addr).name = output[addr]


PluginCommand.register(
    "log2func", "Uses log function's parameter to name corresponding", binja_log2func
)
