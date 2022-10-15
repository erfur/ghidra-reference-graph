import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;

import com.google.gson.Gson;
import ghidra.app.util.headless.HeadlessScript;

public class DumpFunctionOffsets extends HeadlessScript {

    private class FunctionInfo {
        String name;
        long offset;

        public FunctionInfo(String name, long offset) {
            this.name = name;
            this.offset = offset;
        }
    }

    private class ModuleInfo {
        String name;
        ArrayList<FunctionInfo> functions = new ArrayList<>();

        public ModuleInfo(String name) {
            this.name = name;
        }

        public void addFunction(String name, long offset) {
            this.functions.add(new FunctionInfo(name, offset));
        }
    }

    @Override
    public void run() throws Exception {
        setHeadlessContinuationOption(HeadlessContinuationOption.ABORT);

        String[] args = getScriptArgs();
        if (args.length > 0) {
            printf("Args will not be used: %s", String.join(",", args));
            return;
        }

        ModuleInfo module = new ModuleInfo(currentProgram.getName());
        currentProgram.getFunctionManager().getFunctions(true).forEach(elem -> {
            if (!elem.isExternal() && !elem.isThunk() && elem.getBody().getNumAddresses() > 0x20 && elem.getBody().getNumAddresses() < 0x100) {
                String name = elem.getName();
                if (elem.getParentNamespace().getName() != "Global") {
                    name = String.format("%s:%s", elem.getParentNamespace().getName(), name);
                }
                module.addFunction(
                        name,
                        elem.getEntryPoint().subtract(currentProgram.getImageBase()));
            }
        });

        try {
            String fileName = String.format("%s-function_list.json", currentProgram.getName());
            FileWriter fileWriter = new FileWriter(fileName);
            fileWriter.write(new Gson().toJson(module));
            fileWriter.close();
            printf("Saved function offsets to file %s", fileName);
        } catch (IOException e) {
            printf("Failed to write the file.");
            e.printStackTrace();
        }
    }
}
