package me.ayrx.apat.utils;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;

public class APATHelpers {

	public static Function findFunction(String name, Program program) {
		FunctionIterator functions = program.getFunctionManager().getFunctions(true);
		for (Function function : functions) {
			if (function.getName().equals(name)) {
				return function;
			}
		}
		return null;
	}
}
