from binaryninja import open_view
from binaryninja.highlevelil import *
import sys
import argparse
import pickle
from pathlib import Path
import os

def handle_hlil_call(bv, target_func, instr, func_index) -> str:
    if isinstance(instr, HighLevelILCall):
        # Check if it is call to log function
        if isinstance(instr.dest, HighLevelILConstPtr):
            if instr.dest.constant == target_func.start:
                # Check if parameter index exists
                if len(instr.params) - 1 >= func_index:
                    if isinstance(instr.params[func_index], HighLevelILConstPtr):
                        func_name_ptr = instr.params[func_index].constant
                        func_name = bv.get_ascii_string_at(func_name_ptr)
                        if func_name != None:
                            return func_name.value



def log2func(program: str, func_name: str, func_index: int) -> dict:
    bv = open_view(program)
    output_dict = {}
    if bv is None:
        print(f"Could not open view for {program}")
        return output_dict

    funcs = bv.get_functions_by_name(func_name)

    if len(funcs) == 0:
        print(f"Could not find function {func_name}")
        return output_dict

    target_func = funcs[0]

    print(f"Found function {func_name} @ {hex(target_func.start)}")

    caller_funcs = list(set(target_func.callers))

    for func in caller_funcs:
        for bb in func.hlil:
            for instr in bb:
                # Check if it is call
                if isinstance(instr, HighLevelILCall):
                    func_name = handle_hlil_call(bv, target_func, instr, func_index)
                    if func_name is not None:
                        output_dict[func.start] = func_name
                # Unwrap assign
                elif isinstance(instr, HighLevelILAssign):
                    if isinstance(instr.src, HighLevelILCall):
                        func_name = handle_hlil_call(
                            bv, target_func, instr.src, func_index
                        )
                        if func_name is not None:
                            output_dict[func.start] = func_name

    return output_dict


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert log to function")

    parser.add_argument("-p", "--program", help="program or bndb name", required=False)
    parser.add_argument(
        "-f", "--folder", help="folder containing programs or bndb", required=False
    )
    parser.add_argument("-n", "--func_name", help="function name", required=True)
    parser.add_argument(
        "-i", "--func_index", help="function parameter index", type=int, required=True
    )
    parser.add_argument("-o", "--output_path", help="output folder")

    args = parser.parse_args()

    if args.folder:
        files = Path(args.folder).glob("*")
        for f in files:
            output_dict = log2func(str(f), args.func_name, args.func_index)
            if output_dict:
                if args.output_path:
                    with open(f"{args.output_path}/{f.name}.pkl", "wb") as fp:
                        pickle.dump(output_dict, fp, 2)
                else:
                    with open(f"{f.name}.pkl", "wb") as fp:
                        pickle.dump(output_dict, fp, 2)

    elif args.program:
        output_dict = log2func(args.program, args.func_name, args.func_index)
        if args.output_path:
            _, prog_name = os.path.split(args.program)
            with open(f"{args.output_path}/{prog_name}.pkl", "wb") as fp:
                pickle.dump(output_dict, fp, 2)
        else:
            with open(f"{args.program}.pkl", "wb") as fp:
                pickle.dump(output_dict, fp, 2)
    else:
        print("No program or folder specified")
