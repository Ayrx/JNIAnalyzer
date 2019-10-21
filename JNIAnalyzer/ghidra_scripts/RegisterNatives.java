
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
		ArrayList<PcodeOpAST> registerNativesList = new ArrayList<PcodeOpAST>();

		while (ops.hasNext() && !monitor.isCancelled()) {
			PcodeOpAST pcodeOpAST = ops.next();

			if (pcodeOpAST.getOpcode() == PcodeOp.CALLIND) {
				if (this.checkRegisterNatives((VarnodeAST) pcodeOpAST.getInput(0))) {
					registerNativesList.add(pcodeOpAST);
				}
			}
		}

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
		case PcodeOp.INDIRECT:
			// Not quite sure if an INDIRECT call should be handled in this way...
			return this.processVarnode((VarnodeAST) parent.getInput(0));
		default:
			throw new UnsupportedOperationException("Unrecognized op: " + parent.getMnemonic());
		}
	}

	private boolean checkRegisterNatives(VarnodeAST node) throws UnsupportedOperationException {
		if (node.isConstant()) {
			throw new UnsupportedOperationException(
					"Something went wrong. There should not be a constant Varnode here.");
		}

		// TODO: There is definitely a more appropriate way than a string comparison
		// here...
		if (node.getHigh().getDataType().toString().equals("JNIEnv *")) {
			return true;
		}

		PcodeOpAST parent = (PcodeOpAST) node.getDef();

		// If a Varnode is a top level one (i.e. no parent) and hasn't satisfied the
		// DataType == JNIENv * check yet, it probably isn't a RegisterNative call.
		if (parent == null) {
			return false;
		}

		switch (parent.getOpcode()) {
		case PcodeOp.LOAD:
			return this.checkRegisterNatives((VarnodeAST) parent.getInput(1));
		case PcodeOp.PTRSUB:
			boolean isJNIEnv = this.checkRegisterNatives((VarnodeAST) parent.getInput(0));
			// 0x35c is the offset of RegisterNatives from JNIEnv. Reference:
			// https://docs.google.com/spreadsheets/d/1yqjFaY7mqyVIDs5jNjGLT-G8pUaRATzHWGFUgpdJRq8/edit?usp=sharing
			return (isJNIEnv && parent.getInput(1).getOffset() == 0x35c);
		default:
			throw new UnsupportedOperationException("Unrecognized op: " + parent.getMnemonic());
		}
	}
}
