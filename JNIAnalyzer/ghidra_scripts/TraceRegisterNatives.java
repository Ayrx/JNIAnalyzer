
//TraceRegisterNatives.java
//
//@author Ayrx
//@category JNI
//@keybinding
//@menupath
//@toolbar

import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;

import com.google.gson.Gson;
import com.google.gson.stream.JsonReader;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.util.CodeUnitInsertionException;
import me.ayrx.jnianalyzer.JNIUtils;

public class TraceRegisterNatives extends GhidraScript {

	JNIUtils jniUtils;

	private class RegisterNativesCall {
		private String name;
		private String methods_ptr;
		private long nMethods;
		private ArrayList<String> backtrace;
	}

	@Override
	public void run() throws Exception {
		this.jniUtils = new JNIUtils(state, this);

		Address imageBase = this.currentProgram.getImageBase();

		File infoFile = this.askFile("Select trace_registernatives JSON file", "Open");
		Gson gson = new Gson();
		JsonReader reader = new JsonReader(new FileReader(infoFile));

		RegisterNativesCall[] callList = gson.fromJson(reader, RegisterNativesCall[].class);
		for (RegisterNativesCall i : callList) {
			String name = i.name;
			Address methods = imageBase.add(this.getAddressFactory().getAddress(i.methods_ptr).getOffset());
			long nMethods = i.nMethods;

			ArrayList<String> backtrace_t = new ArrayList<String>();
			for (String t : i.backtrace) {
				backtrace_t.add(imageBase.add(this.getAddressFactory().getAddress(t).getOffset()).toString());
			}

			println();
			println("[+] Call to RegisterNatives");
			println("class: " + name);
			println("methods: " + methods.toString());
			println("nMethods: " + String.valueOf(nMethods));
			println("Backtrace: " + String.join(" -> ", backtrace_t));

			try {
				this.jniUtils.applyJNINativeMethodType(methods, nMethods);
				this.createLabel(methods, name.replace(".", "_") + "_METHODS_ARRAY", true);
			} catch (CodeUnitInsertionException e) {
				println("[-] methods memory address " + methods.toString()
						+ " not within the binary. It might be a stack or heap address.");
				continue;
			}
		}
	}
}
