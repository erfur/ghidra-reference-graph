import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Reference;

import org.jgrapht.Graph;
import org.jgrapht.graph.DefaultDirectedGraph;
import org.jgrapht.graph.DefaultEdge;
// import org.jgrapht.graph.SimpleGraph;
import org.jgrapht.nio.Attribute;
import org.jgrapht.nio.DefaultAttribute;
import org.jgrapht.nio.ExportException;
import org.jgrapht.nio.dot.DOTExporter;

import com.google.gson.*;

import java.io.StringWriter;
import java.io.Writer;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;

public class DumpFunctions extends HeadlessScript {

    /**
     * Holds configuration variables.
     */
    private class ScriptConfig {
        public final boolean DISCARD_THUNK_FUNCS = true;
        public final boolean DISCARD_EXTERN_FUNCS = true;
    }

    ScriptConfig sc = new ScriptConfig();

    private class InterestingReference {
        enum RefType {
            DATA2DATA,
            FUNC2FUNC,
            DATA2FUNC,
            FUNC2DATA,
            UNK
        }

        public final RefType type;
        public final Reference reference;

        /**
         * Create an interesting reference from data/functions.
         * 
         * @param type
         * @param ref  Can be Reference or Function.
         */
        public InterestingReference(RefType type, Reference ref) {
            this.type = type;
            this.reference = ref;
        }

        public Address getFromAddress() {
            switch (type) {
                case DATA2DATA:
                case DATA2FUNC:
                    return reference.getFromAddress();
                case FUNC2FUNC:
                case FUNC2DATA:
                    return getFunctionContaining(reference.getFromAddress()).getEntryPoint();
                default:
                    return null;
            }
        }

        public Address getToAddress() {
            switch (type) {
                case DATA2DATA:
                case FUNC2DATA:
                    return reference.getToAddress();
                case FUNC2FUNC:
                case DATA2FUNC:
                    return getFunctionContaining(reference.getToAddress()).getEntryPoint();
                default:
                    return null;
            }
        }

        private static class InterestingReferenceAdapter implements JsonSerializer<InterestingReference> {

            @Override
            public JsonElement serialize(InterestingReference src, Type typeOfSrc,
                    JsonSerializationContext context) {

                JsonObject obj = new JsonObject();
                obj.addProperty("type", src.type.toString());
                obj.addProperty("internalType", src.reference.getReferenceType().toString());
                obj.addProperty("from", src.getFromAddress().getOffset());
                obj.addProperty("to", src.getToAddress().getOffset());

                return obj;
            }
        }

        public static InterestingReferenceAdapter getJsonAdapter() {
            return new InterestingReferenceAdapter();
        }

        // public JsonElement toJsonElement() {
        //     return new GsonBuilder()
        //             .registerTypeAdapter(InterestingReference.class, new InterestingReferenceAdapter())
        //             .create()
        //             .toJsonTree(this);
        // }

        // public String toJson() {
        //     return new GsonBuilder()
        //             .registerTypeAdapter(InterestingReference.class, new InterestingReferenceAdapter())
        //             .create()
        //             .toJson(this);
        // }
    }

    private class InterestingReferenceContainer {
        public ArrayList<InterestingReference> refs = new ArrayList<>();

        public void add(InterestingReference ref) {
            refs.add(ref);
        }

        public void forEach(java.util.function.Consumer<? super InterestingReference> action) {
            refs.forEach(action);
        }

        public JsonElement toJsonElement() {
            return new GsonBuilder()
                    .registerTypeAdapter(InterestingReference.class, InterestingReference.getJsonAdapter())
                    .create()
                    .toJsonTree(this);
        }
    }

    private class InterestingFunction {
        public Function function;
        public InterestingReferenceContainer refs = new InterestingReferenceContainer();

        /**
         * Build our own object from an interesting Function.
         * This is done to have a serializable data structure.
         * 
         * @param f a ghidra Function
         */
        public InterestingFunction(Function f) {
            function = f;

            // populate references
            findRefsFrom(function);
            findRefsTo(function);
        }

        public String getName() {
            return function.getName();
        }

        public Long getOffset() {
            return function.getEntryPoint().getOffset();
        }

        public void addRef(InterestingReference ref) {
            refs.add(ref);
        }

        /**
         * Find references to data by iterating through every byte in its address range.
         * 
         * @param f
         */
        private void findRefsFrom(Function f) {
            f.getBody().getAddressRanges().forEach(addrRange -> {
                // print the range
                printf("Address range %x-%x",
                        addrRange.getMinAddress().getOffset(),
                        addrRange.getMaxAddress().getOffset());

                // pull references from each address in range
                addrRange.forEach(addr -> {
                    Reference[] refs = getReferencesFrom(addr);
                    for (int i = 0; i < refs.length; i++) {

                        Reference ref = refs[i];

                        printf("Reference to %x from %x, type %s",
                                ref.getToAddress().getOffset(),
                                ref.getFromAddress().getOffset(),
                                ref.getReferenceType().toString());

                        // seems like this works
                        if (ref.isMemoryReference()
                                && !ref.isOffsetReference()
                                && ref.getReferenceType().isData()
                                && !ref.getReferenceType().isWrite()
                                // && !ref.getReferenceType().isRead()
                                && !ref.getReferenceType().isCall()
                                && !ref.getReferenceType().isJump()) {
                            // may need to filter out uninitialized data or other things
                            addRef(new InterestingReference(InterestingReference.RefType.FUNC2DATA, ref));
                        }
                    }
                });
            });
        }

        /**
         * Find references to the function and make decisions based on results.
         */
        private void findRefsTo(Function f) {
            Reference[] refs = getReferencesTo(f.getEntryPoint());
            for (Reference ref : refs) {
                Address addr = ref.getFromAddress();

                // If the reference origin is contained within a function then
                // add the function as a reference.
                Function srcFunction = getFunctionContaining(addr);
                if (srcFunction != null) {
                    addRef(new InterestingReference(InterestingReference.RefType.FUNC2FUNC, ref));
                } else {
                    addRef(new InterestingReference(InterestingReference.RefType.DATA2FUNC, ref));
                }
            }
        }

        private static class InterestingFunctionAdapter implements JsonSerializer<InterestingFunction> {
            @Override
            public JsonElement serialize(InterestingFunction src, Type typeOfSrc,
                    JsonSerializationContext context) {

                JsonObject obj = new JsonObject();
                obj.addProperty("name", src.getName());
                obj.addProperty("addr", src.getOffset());
                obj.add("refs", src.refs.toJsonElement());
                return obj;
            }
        }

        public static InterestingFunctionAdapter getJsonAdapter() {
            return new InterestingFunctionAdapter();
        }

        // public JsonElement toJsonElement() {
        //     return new GsonBuilder()
        //             .registerTypeAdapter(InterestingFunction.class, new InterestingFunctionAdapter())
        //             .create()
        //             .toJsonTree(this);
        // }

        // public String toJson() {
        //     return new GsonBuilder()
        //             .registerTypeAdapter(InterestingFunction.class, getJsonAdapter())
        //             .create()
        //             .toJson(this);
        // }
    }

    private class InterestingFunctionContainer {
        ArrayList<InterestingFunction> interestingFunctions = new ArrayList<InterestingFunction>();

        public void add(Function f) {
            interestingFunctions.add(new InterestingFunction(f));
        }

        public int getSize() {
            return interestingFunctions.size();
        }

        public void forEach(java.util.function.Consumer<? super InterestingFunction> action) {
            interestingFunctions.forEach(action);
        }

        public JsonElement toJsonElement() {
            return new GsonBuilder()
                    .registerTypeAdapter(InterestingFunction.class, InterestingFunction.getJsonAdapter())
                    .create()
                    .toJsonTree(this);
        }

        public String toJson() {
            return new GsonBuilder()
                    .registerTypeAdapter(InterestingFunction.class, InterestingFunction.getJsonAdapter())
                    .create()
                    .toJson(interestingFunctions);
        }
    }

    InterestingFunctionContainer interestingFunctions = new InterestingFunctionContainer();

    @Override
    public void run() throws Exception {
        setHeadlessContinuationOption(HeadlessContinuationOption.ABORT);

        String[] args = getScriptArgs();
        if (args.length > 0) {
            printf("Args will not be used: %s", String.join(",", args));
            return;
        }

        // DecompInterface decompiler = new DecompInterface();
        FunctionManager functionManager = currentProgram.getFunctionManager();

        printf("function count: %d", functionManager.getFunctionCount());

        FunctionIterator funcs = functionManager.getFunctions(true);
        while (funcs.hasNext()) {
            Function f = funcs.next();

            if (sc.DISCARD_EXTERN_FUNCS && f.isExternal()) {
                continue;
            } else if (sc.DISCARD_THUNK_FUNCS && f.isThunk()) {
                continue;
            } else {
                interestingFunctions.add(f);
            }
        }

        printf("no. of interesting functions: %d", interestingFunctions.getSize());

        // print as json
        printf(interestingFunctions.toJson());

        // print as dot
        graphix();
    }

    /**
     * Build a graph from interesting functions and references.
     */
    private void graphix() {
        Graph<String, DefaultEdge> g = new DefaultDirectedGraph<>(DefaultEdge.class);

        interestingFunctions.forEach(ifunc -> {
            ifunc.refs.forEach(ref -> {
                String from, to;
                switch (ref.type) {
                    case FUNC2DATA:
                        from = String.format("\"fcn @0x%x\"", ifunc.getOffset());
                        to = String.format("\"dat @0x%x\"", ref.getToAddress().getOffset());
                        g.addVertex(from);
                        g.addVertex(to);
                        g.addEdge(from, to);
                        break;
                    case FUNC2FUNC:
                        from = String.format("\"fcn @0x%x\"", ifunc.getOffset());
                        to = String.format("\"fcn @0x%x\"", ref.getToAddress().getOffset());
                        g.addVertex(from);
                        g.addVertex(to);
                        g.addEdge(from, to);
                        break;
                    case DATA2FUNC:
                        from = String.format("\"dat @0x%x\"", ref.getFromAddress().getOffset());
                        to = String.format("\"fcn @0x%x\"", ref.getToAddress().getOffset());
                        g.addVertex(from);
                        g.addVertex(to);
                        g.addEdge(from, to);
                        break;
                    case DATA2DATA:
                    default:
                }
            });
        });

        renderGraph(g);
    }

    /**
     * Render a graph in DOT format.
     *
     * @param graph a graph based on URI objects
     */
    private void renderGraph(Graph<String, DefaultEdge> graph)
            throws ExportException {

        DOTExporter<String, DefaultEdge> exporter = new DOTExporter<>(v -> v);
        exporter.setVertexAttributeProvider((v) -> {
            Map<String, Attribute> map = new LinkedHashMap<>();
            map.put("label", DefaultAttribute.createAttribute(v.toString()));
            return map;
        });
        Writer writer = new StringWriter();
        exporter.exportGraph(graph, writer);
        println(writer.toString());
    }
}
