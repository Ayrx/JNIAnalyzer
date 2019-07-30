package me.ayrx.apat.utils;

import java.util.ArrayList;
import java.util.HashMap;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;

/**
 * A look-up table for Functions in a Program.
 *
 */
public class FunctionMap {

	public HashMap<String, Function> funcMap;
	public ArrayList<Function> dupeFunctions;

	/**
	 * Stores a map of functions in the provided program.
	 *
	 * If there is a function with a duplicate name, which typically happens with a
	 * thunk function, the first function with the name is stored. The extra
	 * function(s) are stored in the dupeFunctions list.
	 *
	 * @param p - the Program to parse
	 */
	public FunctionMap(Program p) {
		funcMap = new HashMap<String, Function>();
		dupeFunctions = new ArrayList<Function>();

		FunctionIterator functions = p.getFunctionManager().getFunctions(true);
		for (Function function : functions) {
			Function v = funcMap.putIfAbsent(function.getName(), function);
			if (v != null) {
				dupeFunctions.add(v);
			}
		}
	}

	public Function get(String name) {
		return funcMap.get(name);
	}

	/**
	 * Returns a list of functions with "duplicate" names.
	 *
	 * @return
	 */
	public ArrayList<Function> getDupeFunctions() {
		return dupeFunctions;
	}

	/**
	 * Overrides the map with the provided function.
	 *
	 * This is useful if the default behaviour of inserting the first function is
	 * "wrong".
	 *
	 * @param f
	 */
	public void forceInsert(Function f) {
		funcMap.put(f.getName(), f);
	}
}
