from .log2func import log2func
from binaryninja import PluginCommand

def binja_log2func(bv):
    print(len(log2func(bv, "debug_printf", 2)))

PluginCommand.register(
    "log2func", "Uses log function's parameter to name corresponding", binja_log2func
)