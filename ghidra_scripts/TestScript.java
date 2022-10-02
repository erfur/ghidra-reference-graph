// Test script.
//
//@category Test
//@keybinding ctrl shift T
//@menupath File.Run.Test
//@toolbar ok.gif

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOpAST;

import java.util.Iterator;

public class TestScript extends GhidraScript {

    @Override
    public void run() throws Exception {

        DecompInterface ifc = new DecompInterface();
        try {
            Function function = currentProgram.getFunctionManager()
                                              .getFunctionContaining(currentAddress);
            println(String.format("Decompiling %s at %s",
                                  function.getName(),
                                  function.getEntryPoint()));
            ifc.openProgram(currentProgram);
            DecompileResults decompileResults = ifc.decompileFunction(function, 30, monitor);
            println("Decompilation completed: " + decompileResults.decompileCompleted());
            Iterator<PcodeOpAST> pcodeOpASTIterator = decompileResults.getHighFunction()
                                                                      .getPcodeOps();
            StringBuilder pcodeHighString = new StringBuilder();
            while (pcodeOpASTIterator.hasNext()) {
                PcodeOpAST pcodeOpAST = pcodeOpASTIterator.next();
                pcodeHighString.append(String.format("%s\n", pcodeOpAST));
            }
            println(pcodeHighString.toString());
        } finally {
            ifc.dispose();
        }
    }
}
