
//This script reads the output of `FindNativeJNIMethods.jar` and applies the
//function signature to all matching functions.
//
//@author Ayrx
//@category JNI
//@keybinding
//@menupath
//@toolbar

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;

import com.google.gson.Gson;
import com.google.gson.stream.JsonReader;

import ghidra.app.plugin.core.datamgr.archive.Archive;
import ghidra.app.plugin.core.datamgr.archive.DuplicateIdException;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.DataTypeManagerService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class JNIAnalyzer extends GhidraScript {

	DataTypeManager manager;

	private class MethodInformation {
		private String methodName;
		private ArrayList<String> argumentTypes;
		private String returnType;
		private boolean isStatic;
	}

	private class NativeMethodsList {
		ArrayList<MethodInformation> methods = new ArrayList<>();
	}

	@Override
	public void run() throws Exception {
		println("[+] Import jni_all.h...");
		this.manager = this.getDataTypeManageFromArchiveFile();

		File infoFile = this.askFile("Select method argument file", "Open");
		Gson gson = new Gson();
		JsonReader reader = new JsonReader(new FileReader(infoFile));

		NativeMethodsList methodsList = gson.fromJson(reader, NativeMethodsList.class);

		println("[+] Enumerating JNI functions...");
		HashMap<String, Function> functions = new HashMap<String, Function>();
		ArrayList<String> ignoredFunctions = new ArrayList<String>();

		Function function = this.getFirstFunction();
		while (function != null) {
			if (function.getName().startsWith("Java_")) {

				String comment = function.getComment();
				if (comment != null && comment.contains("JNIAnalyzer:IGNORE")) {
					ignoredFunctions.add(function.getName());
				} else {
					functions.put(function.getName(), function);
					println(function.getName());
				}
			}

			if (function.getName().equals("JNI_OnLoad")) {
				this.applyJNIOnLoadSignature(function);
			}

			function = this.getFunctionAfter(function);
		}
		println("Total JNI functions found: " + functions.size());
		println("Ignored JNI functions:");
		for (String name : ignoredFunctions) {
			println(name);
		}
		println();

		println("[+] Applying function signatures...");
		for (MethodInformation method : methodsList.methods) {
			String methodName = method.methodName;
			String[] methodNameSplit = methodName.split("\\.");
			methodName = "Java_" + String.join("_", methodNameSplit);

			if (functions.containsKey(methodName)) {
				Function f = functions.get(methodName);

				Parameter[] params = new Parameter[method.argumentTypes.size() + 2]; // + 2 to accomodate env and thiz

				params[0] = new ParameterImpl("env", this.manager.getDataType("/jni_all.h/JNIEnv *"),
						this.currentProgram, SourceType.USER_DEFINED);

				if (method.isStatic) {
					params[1] = new ParameterImpl("thiz", this.manager.getDataType("/jni_all.h/jclass"),
							this.currentProgram, SourceType.USER_DEFINED);
				} else {
					params[1] = new ParameterImpl("thiz", this.manager.getDataType("/jni_all.h/jobject"),
							this.currentProgram, SourceType.USER_DEFINED);
				}

				for (int i = 0; i < method.argumentTypes.size(); i++) {
					String argType = method.argumentTypes.get(i);

					params[i + 2] = new ParameterImpl("a" + String.valueOf(i),
							this.manager.getDataType("/jni_all.h/" + argType), this.currentProgram,
							SourceType.USER_DEFINED);
				}

				Parameter returnType = new ReturnParameterImpl(
						this.manager.getDataType("/jni_all.h/" + method.returnType), this.currentProgram);

				f.updateFunction(null, returnType, Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true,
						SourceType.USER_DEFINED, params);
			}
		}
	}

	private DataTypeManager getDataTypeManageFromArchiveFile() throws IOException, DuplicateIdException {
		PluginTool tool = this.state.getTool();
		DataTypeManagerService service = tool.getService(DataTypeManagerService.class);

		// Look for an already open "jni_all" archive.
		DataTypeManager[] managers = service.getDataTypeManagers();
		for (DataTypeManager m : managers) {
			if (m.getName().equals("jni_all")) {
				return m;
			}
		}

		// If an existing archive isn't found, open it from the file.
		URL jniArchiveURL = ClassLoader.getSystemClassLoader().getResource("jni_all.gdt");
		File jniArchiveFile = new File(jniArchiveURL.getFile());

		Archive jniArchive = service.openArchive(jniArchiveFile, false);
		return jniArchive.getDataTypeManager();
	}

	private void applyJNIOnLoadSignature(Function function) throws DuplicateNameException, InvalidInputException {
		println("Modified " + function.getName());

		Parameter arg0 = function.getParameter(0);
		arg0.setName("vm", SourceType.USER_DEFINED);
		arg0.setDataType(this.manager.getDataType("/jni_all.h/JavaVM *"), SourceType.USER_DEFINED);
	}
}
