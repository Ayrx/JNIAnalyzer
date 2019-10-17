
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
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.VarnodeAST;
import me.ayrx.apat.decompiler.DecompilerHelper;

public class RegisterNatives extends GhidraScript {

	private DecompInterface decomplib;

	private class PcodeVarnodeTuple {
		public PcodeOpAST pcode;
		public VarnodeAST varnode;

		public PcodeVarnodeTuple(PcodeOpAST p, VarnodeAST v) {
			this.pcode = p;
			this.varnode = v;
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

		println(String.valueOf(registerNativesList.size()));
	}

	private ArrayList<PcodeOpAST> findRegisterNatives(Iterator<PcodeOpAST> ops) {
		ArrayList<PcodeOpAST> registerNativesList = new ArrayList<PcodeOpAST>();

		while (ops.hasNext() && !monitor.isCancelled()) {
			PcodeOpAST pcodeOpAST = ops.next();

			if (pcodeOpAST.getOpcode() == PcodeOp.CALLIND) {
				ArrayList<PcodeVarnodeTuple> list = new ArrayList<PcodeVarnodeTuple>();

				VarnodeAST node = (VarnodeAST) pcodeOpAST.getInput(0);
				list.add(new PcodeVarnodeTuple(pcodeOpAST, node));

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
						println("Unrecognized op: " + p.getMnemonic());
						return null;
					}

					list.add(new PcodeVarnodeTuple(p, node));
					if (node.getHigh().getDataType().toString().equals("JNIEnv *")) {
						break;
					}
				}

				for (PcodeVarnodeTuple t : list) {
					PcodeOpAST p = t.pcode;
					// 0x35c is the offset of RegisterNatives from JNIEnv. Reference:
					// https://docs.google.com/spreadsheets/d/1yqjFaY7mqyVIDs5jNjGLT-G8pUaRATzHWGFUgpdJRq8/edit?usp=sharing
					if (p.getOpcode() == PcodeOp.PTRSUB && p.getInput(1).getOffset() == 0x35c) {
						registerNativesList.add(list.get(0).pcode);
					}
				}
			}
		}

		return registerNativesList;
	}
}
