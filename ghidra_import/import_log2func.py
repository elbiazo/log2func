#TODO write a description for this script
#@author 
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 


#TODO Add User Code Here
import pickle
from ghidra.program.model.symbol import SourceType

# helper function to get a Ghidra Address type
def getAddress(offset):
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset)

# get a FunctionManager reference for the current program
functionManager = currentProgram.getFunctionManager()

pkl_file = askFile("Import Pickle File", "Give me the pkl file")

output_dict = pickle.load(open(str(pkl_file), "rb"))

for addr_int in output_dict.keys():
	addr = getAddress(addr_int)
	if functionManager.isInFunction(addr):
		func = functionManager.getFunctionContaining(addr)
		func.setName(output_dict[addr_int], SourceType.ANALYSIS)
	else:
		createFunction(addr, output_dict[addr_int])


	print("{} -> {}".format(hex(addr_int), output_dict[addr_int]))
	
