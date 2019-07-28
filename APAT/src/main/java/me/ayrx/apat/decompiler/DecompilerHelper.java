package me.ayrx.apat.decompiler;

import ghidra.app.decompiler.DecompInterface;

public class DecompilerHelper {

	public static DecompInterface defaultDecompiler() {
		DecompInterface decompInterface = new DecompInterface();

		decompInterface.toggleSyntaxTree(true);
		decompInterface.toggleCCode(true);
		decompInterface.toggleParamMeasures(false);
		decompInterface.toggleJumpLoads(false);

		decompInterface.setSimplificationStyle("decompile");

		return decompInterface;
	}
}
