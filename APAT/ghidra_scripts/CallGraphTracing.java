
//Trace all call paths between two functions.
//
//This script performs a Breadth-first search (BFS) to locate potential
//call paths between two functions.
//
//To use this script, define the starting function in the `sourceFuncName`
//variable and the ending function in the `sinkFuncName` variable. The
//call depth can be controlled by changing the `searchDepth` variable.
//
//@author Ayrx
//@category APAT
//@keybinding
//@menupath
//@toolbar

import java.util.ArrayDeque;
import java.util.LinkedList;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import me.ayrx.apat.utils.FunctionMap;

public class CallGraphTracing extends GhidraScript {

	String sourceFuncName = "main";
	String sinkFuncName = "target";
	int searchDepth = 10;

	@Override
	public void run() throws Exception {

		FunctionMap funcMap = new FunctionMap(this.currentProgram);
		Function sourceFunc = funcMap.get(sourceFuncName);
		Function sinkFunc = funcMap.get(sinkFuncName);

		if (sourceFunc == null || sinkFunc == null) {
			println("[+] Unable to find sink or source function.");
			return;
		}

		println("[+] Source: " + sourceFunc.getName());
		println("[+] Sink: " + sinkFunc.getName());

		ArrayDeque<LinkedList<Function>> queue = new ArrayDeque<LinkedList<Function>>();
		LinkedList<Function> currPath = new LinkedList<Function>();

		currPath.add(sourceFunc);
		queue.add(currPath);

		while (!queue.isEmpty()) {
			LinkedList<Function> v = queue.remove();

			if (v.size() > searchDepth) {
				println("[+] Hit max search depth. Exiting.");
				return;
			}

			if (v.getLast().equals(sinkFunc)) {
				println("[+] Found path:");

				while (!v.isEmpty()) {
					println(v.remove().toString());
				}

			} else {
				for (Function f : v.getLast().getCalledFunctions(this.monitor)) {
					LinkedList<Function> n = (LinkedList<Function>) v.clone();
					n.add(f);
					queue.add(n);
				}
			}

		}
	}

}
