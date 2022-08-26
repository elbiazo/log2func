# TODO write a description for this script
# @author
# @category _NEW_
# @keybinding
# @menupath
# @toolbar


from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.script import GhidraScript
from ghidra.program.model.pcode import *
from ghidra.program.model.symbol import *


def get_vn_data(vn):
    if not vn:
        return None
    copyPcode = vn.getDef()
    if copyPcode == None:
        return None

    vnIn = copyPcode.getInput(0)

    if not vnIn.isConstant() and not vnIn.isAddress():
        return None

    func_addr = vnIn.getAddress()
    if func_addr == None:
        return None

    # Cant get string at const addr space to toAddr will convert it into ram address space
    func_addr = toAddr(func_addr.getOffset())
    func_name = getDataAt(func_addr)
    if not func_name:
        return None

    return func_name


def isTargetFunction(vn, funcName):
    if not vn.isAddress():
        return false
    else:
        addr = vn.getAddress()
        fnc = getSymbolAt(addr)

        if fnc == None:
            return false

        return funcName in fnc.toString()


def get_func_name(currentProgram, curFunction):
    ifc = DecompInterface()
    options = DecompileOptions()

    ifc.setOptions(options)
    ifc.openProgram(currentProgram)
    ifc.setSimplificationStyle("decompile")

    monitor = ConsoleTaskMonitor()
    res = ifc.decompileFunction(curFunction, 30, monitor)

    highFunction = res.getHighFunction()

    if not highFunction:
        raise Exception("high function is none")

    pcodeOps = highFunction.getPcodeOps()

    while pcodeOps.hasNext():
        pcodeElem = pcodeOps.next()
        opcode = pcodeElem.getOpcode()

        if opcode != PcodeOp.CALL and opcode != PcodeOp.CALLIND:
            continue

        vn = pcodeElem.getInput(0)
        if isTargetFunction(vn, "log"):
            funcName = get_vn_data(pcodeElem.getInput(3))
            if funcName:
                return funcName.getValue()


# def log2func(log_name, func_name_indexc):
if __name__ == '__main__':

    cur_func = getFunctionContaining(currentAddress)

    func_name = get_func_name(currentProgram, cur_func)
    cur_func.setName(func_name, ghidra.program.model.symbol.SourceType.DEFAULT)
