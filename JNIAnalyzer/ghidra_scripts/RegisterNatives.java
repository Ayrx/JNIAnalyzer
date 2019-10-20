
//WIP: RegisterNatives.java
//
//@author Ayrx
//@category JNI
//@keybinding
//@menupath
//@toolbar

import java.util.ArrayList;
import java.util.Iterator;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.VarnodeAST;
import ghidra.program.model.scalar.Scalar;
import me.ayrx.apat.decompiler.DecompilerHelper;

public class RegisterNatives extends GhidraScript {

	private DecompInterface decomplib;

	class UnsupportedOperationException extends Exception {
		public UnsupportedOperationException(String message) {
			super(message);
		}
	}

	@Override
	public void run() throws Exception {
		this.decomplib = DecompilerHelper.defaultDecompiler();
		this.decomplib.openProgram(this.currentProgram);

		Function currentFunction = this.getFunctionContaining(this.currentAddress);

		DecompileResults dRes = this.decomplib.decompileFunction(currentFunction, 60, this.getMonitor());

		HighFunction hFunction = dRes.getHighFunction();

		Iterator<PcodeOpAST> ops = hFunction.getPcodeOps();
		ArrayList<PcodeOpAST> registerNativesList = this.findRegisterNatives(ops);

		println("[+] Found " + String.valueOf(registerNativesList.size()) + " calls to RegisterNatives");

		for (PcodeOpAST pc : registerNativesList) {
			println(pc.toString());

			VarnodeAST node = (VarnodeAST) pc.getInput(3);
			Address methodPtr = this.toAddr(this.processVarnode(node));
			println(methodPtr.toString());
		}
	}

	/**
	 * Process the Varnode that represents the methods pointer in the call to
	 * RegisterNatives.
	 *
	 * We recursively traverse the AST until we find the Varnode that is either a
	 * constant or does not have a parent which should indicate a stopping point.
	 */
	private long processVarnode(VarnodeAST node) throws UnsupportedOperationException {
		if (node.isConstant()) {
			return node.getOffset();
		}

		PcodeOpAST parent = (PcodeOpAST) node.getDef();
		if (parent == null && node.isAddress()) {
			Data d = this.getDataAt(node.getAddress());
			return ((Scalar) d.getValue()).getValue();
		}

		switch (parent.getOpcode()) {
		case PcodeOp.CAST:
		case PcodeOp.COPY:
			return this.processVarnode((VarnodeAST) parent.getInput(0));
		case PcodeOp.INT_ADD:
		case PcodeOp.PTRSUB:
			long a1 = this.processVarnode((VarnodeAST) parent.getInput(0));
			long b1 = this.processVarnode((VarnodeAST) parent.getInput(1));
			return a1 + b1;
		case PcodeOp.PTRADD:
			long a2 = this.processVarnode((VarnodeAST) parent.getInput(0));
			long b2 = this.processVarnode((VarnodeAST) parent.getInput(1));
			long c2 = this.processVarnode((VarnodeAST) parent.getInput(2));
			return a2 + b2 * c2;
		default:
			throw new UnsupportedOperationException("Unrecognized op: " + parent.getMnemonic());
		}
	}

	private ArrayList<PcodeOpAST> findRegisterNatives(Iterator<PcodeOpAST> ops) throws UnsupportedOperationException {
		ArrayList<PcodeOpAST> registerNativesList = new ArrayList<PcodeOpAST>();

		while (ops.hasNext() && !monitor.isCancelled()) {
			PcodeOpAST pcodeOpAST = ops.next();

			if (pcodeOpAST.getOpcode() == PcodeOp.CALLIND) {
				ArrayList<PcodeOpAST> list = new ArrayList<PcodeOpAST>();

				VarnodeAST node = (VarnodeAST) pcodeOpAST.getInput(0);
				list.add(pcodeOpAST);

				while (true) {
					PcodeOpAST p = (PcodeOpAST) node.getDef();

					switch (p.getOpcode()) {
					case PcodeOp.LOAD:
						node = (VarnodeAST) p.getInput(1);
						break;
					case PcodeOp.PTRSUB:
						node = (VarnodeAST) p.getInput(0);
						break;
					default:
						throw new UnsupportedOperationException("Unrecognized op: " + p.getMnemonic());
					}

					list.add(p);
					if (node.getHigh().getDataType().toString().equals("JNIEnv *")) {
						break;
					}
				}

				for (PcodeOpAST p : list) {
					// We definitely want to change this to actually walk down the AST instead of
					// assuming there is only one PTRSUB once we account for more P-Code opcodes.
					//
					// 0x35c is the offset of RegisterNatives from JNIEnv. Reference:
					// https://docs.google.com/spreadsheets/d/1yqjFaY7mqyVIDs5jNjGLT-G8pUaRATzHWGFUgpdJRq8/edit?usp=sharing
					if (p.getOpcode() == PcodeOp.PTRSUB && p.getInput(1).getOffset() == 0x35c) {
						registerNativesList.add(list.get(0));
					}
				}
			}
		}

		return registerNativesList;
	}
}
