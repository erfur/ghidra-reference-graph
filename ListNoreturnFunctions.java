// Test script.
//
//@category Test
//@keybinding ctrl shift T
//@menupath Plugins.FixNoreturn
//@toolbar ok.gif

import ghidra.app.cmd.disassemble.SetFlowOverrideCmd;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.address.Address;

import ghidra.program.model.address.*;
import ghidra.program.model.block.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;


import java.util.Iterator;

public class FixNoreturn extends GhidraScript {

    @Override
    public void run() throws Exception {

        currentProgram.getFunctionManager().getFunctions(false).forEach(fcn -> {
            if (fcn.hasNoReturn()) {
                println(String.format("Fcn is noreturn: %s", fcn.toString()));
            }
        });

        // currentProgram.getReferenceManager().getReferencesTo(currentAddress).forEach(ref -> {
        //     if (ref.getReferenceType().isCall()) {
        //         Address addr = ref.getFromAddress();
        //         Function fcn = currentProgram.getFunctionManager().getFunctionContaining(addr);

        //         Instruction instr = currentProgram.getListing().getInstructionAt(addr);
                
        //         if (instr != null) {
        //             println(String.format("Processing %s at %s", instr.toString(), instr.getAddress().toString()));
        //             currentProgram.getListing().clearCodeUnits(addr, addr.add(5), true);
        //             DisassembleCommand cmd = new DisassembleCommand(addr, null, false);
        //             cmd.applyTo(currentProgram, monitor);        
        //             // new SetFlowOverrideCmd(addr, FlowOverride.NONE).applyTo(currentProgram, monitor);
        //             // instr.setFlowOverride(FlowOverride.NONE);
        //             // println(String.format("Changed to %s", instr.getFlowOverride().toString()));
        //         } else {
        //             println(String.format("Cant find function at %s", addr.toString()));
        //         }
        //     }
        // });
    }
}
