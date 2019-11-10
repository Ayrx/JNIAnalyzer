
//WIP: RegisterNatives.java
//
//@author Ayrx
//@category JNI
//@keybinding
//@menupath
//@toolbar

import java.util.ArrayList;
import java.util.Iterator;
import java.util.Set;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighParam;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.VarnodeAST;
import ghidra.program.model.scalar.Scalar;
import me.ayrx.apat.decompiler.DecompilerHelper;

public class RegisterNatives extends GhidraScript {

	private DecompInterface decomplib;
	private DataType jniNativeMethodType;

	class UnsupportedOperationException extends Exception {
		public UnsupportedOperationException(String message) {
			super(message);
		}
	}

	class VarnodeIsParamException extends Exception {
		public VarnodeAST n;

		public VarnodeIsParamException(VarnodeAST n) {
			this.n = n;
		}
	}

	class MethodsArrayPair {
		public long addr;
		public long length;

		public MethodsArrayPair(long addr, long length) {
			this.addr = addr;
			this.length = length;
		}
	}

	@Override
	public void run() throws Exception {
		DataType[] d = this.getDataTypes("JNINativeMethod");
		if (d.length != 1) {
			println("[-] Error: Please import jni_all.h first.");
		}
		this.jniNativeMethodType = d[0];

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

			// Trace the origin of the `methods` param of the RegisterNatives call.
			VarnodeAST methodsNode = (VarnodeAST) pc.getInput(3);
			VarnodeAST nMethodsNode = (VarnodeAST) pc.getInput(4);

			try {
				// Happy case where the `methods` ends up at a constant.
				long methods = this.processVarnode(methodsNode);

				// If `methods` is not a parameter, `nMethods` is most likely to be a
				// constant as well.
				long nMethods = this.processVarnode(nMethodsNode);

				this.applyRegisterNatives(methods, nMethods);
			} catch (VarnodeIsParamException e) {
				// Case where `methods` is a parameter to the current function.
				VarnodeAST methodsParam = e.n;
				VarnodeAST nMethodsParam = null;

				try {
					this.processVarnode(nMethodsNode);
				} catch (VarnodeIsParamException ee) {
					// Logically this should always happen. It is very weird if `methods` is from a
					// param but `nMethods` is a constant...
					nMethodsParam = ee.n;
				}

				ArrayList<MethodsArrayPair> params = this.processParam(methodsParam, nMethodsParam);
				for (MethodsArrayPair i : params) {
					long methods = i.addr;
					long nMethods = i.length;

					this.applyRegisterNatives(methods, nMethods);
				}

				return;
			}
		}
	}

	private void applyRegisterNatives(long methods, long nMethods) throws Exception {
		Address methodPtr = this.toAddr(methods);

		println("[+] Applying datatype to " + methodPtr.toString() + ". Length: " + String.valueOf(nMethods) + ".");

		long offset = (jniNativeMethodType.getLength() * nMethods) - this.currentProgram.getDefaultPointerSize();
		this.clearListing(methodPtr, methodPtr.add(offset));

		Address currentPtr = methodPtr;
		for (int i = 0; i < nMethods; i++) {
			this.createData(currentPtr, jniNativeMethodType);
			currentPtr = currentPtr.add(jniNativeMethodType.getLength());
		}
	}

	/**
	 * Process the Varnode that represents the methods pointer in the call to
	 * RegisterNatives.
	 *
	 * We recursively traverse the AST until we find the Varnode that is either a
	 * constant or does not have a parent which should indicate a stopping point.
	 */
	private long processVarnode(VarnodeAST node) throws UnsupportedOperationException, VarnodeIsParamException {
		if (node.isConstant()) {
			return node.getOffset();
		}

		if (node.getHigh() instanceof HighParam) {
			throw new VarnodeIsParamException(node);
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

	private ArrayList<MethodsArrayPair> processParam(VarnodeAST methodsNode, VarnodeAST nMethodsNode)
			throws UnsupportedOperationException {
		HighParam methodsParam = (HighParam) methodsNode.getHigh();
		HighParam nMethodsParam = (HighParam) nMethodsNode.getHigh();

		int methodsSlot = methodsParam.getSlot();
		int nMethodsSlot = nMethodsParam.getSlot();

		Function f = methodsNode.getHigh().getHighFunction().getFunction();
		Address fAddress = f.getEntryPoint();
		Set<Function> callers = f.getCallingFunctions(this.monitor);

		ArrayList<MethodsArrayPair> ret = new ArrayList<MethodsArrayPair>();
		for (Function fc : callers) {
			DecompileResults dRes = this.decomplib.decompileFunction(fc, 60, this.monitor);
			HighFunction hF = dRes.getHighFunction();
			Iterator<PcodeOpAST> ops = hF.getPcodeOps();
			while (ops.hasNext() && !monitor.isCancelled()) {
				PcodeOpAST pcodeOpAST = ops.next();
				if (pcodeOpAST.getOpcode() == PcodeOp.CALL && pcodeOpAST.getInput(0).getAddress().equals(fAddress)) {

					methodsNode = (VarnodeAST) pcodeOpAST.getInput(3);
					nMethodsNode = (VarnodeAST) pcodeOpAST.getInput(4);

					try {
						// Happy case where the `methods` ends up at a constant.
						long methods = this.processVarnode(methodsNode);
						long nMethods = this.processVarnode(nMethodsNode);
						MethodsArrayPair i = new MethodsArrayPair(methods, nMethods);
						ret.add(i);
					} catch (VarnodeIsParamException e) {
						// Case where `methods` is a parameter to the current function.
						VarnodeAST methodsParamNext = e.n;
						VarnodeAST nMethodsParamNext = null;

						try {
							this.processVarnode(nMethodsNode);
						} catch (VarnodeIsParamException ee) {
							// Logically this should always happen. It is very weird if `methods` is from a
							// param but `nMethods` is a constant...
							nMethodsParamNext = ee.n;
						}

						ret.addAll(this.processParam(methodsParamNext, nMethodsParamNext));
					}
				}
			}
		}

		return ret;
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
