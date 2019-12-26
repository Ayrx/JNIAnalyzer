
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
import java.util.ArrayList;
import java.util.HashMap;

import com.google.gson.Gson;
import com.google.gson.stream.JsonReader;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import me.ayrx.jnianalyzer.JNIUtils;

public class JNIAnalyzer extends GhidraScript {

	DataTypeManager manager;
	JNIUtils jniUtils;

	private class MethodInformation {
		private String methodName;
		private String argumentSignature;
		private ArrayList<String> argumentTypes;
		private String returnType;
		private boolean isStatic;
	}

	private class NativeMethodsList {
		ArrayList<MethodInformation> methods = new ArrayList<>();
	}

	@Override
	public void run() throws Exception {
		this.jniUtils = new JNIUtils(state, this);

		println("[+] Import jni_all.h...");
		this.manager = this.jniUtils.getDataTypeManageFromArchiveFile();

		File infoFile = this.askFile("Select method argument file", "Open");
		Gson gson = new Gson();
		JsonReader reader = new JsonReader(new FileReader(infoFile));

		NativeMethodsList methodsList = gson.fromJson(reader, NativeMethodsList.class);

		// Iterate through all functions in the binary and look for the ones starting
		// with "Java_". Ignore the functions marked with "JNIAnalyzer:IGNORE".
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

			String functionName = function.getName();
			if (functionName.equals("JNI_OnLoad") || functionName.equals("JNI_OnUnload")) {
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

		// Bucket the Methods parsed from the JSON based on the method name.
		// This will allow us to determine if we need to use the overloaded
		// form the name mangling.
		HashMap<String, ArrayList<MethodInformation>> methodMap = new HashMap<String, ArrayList<MethodInformation>>();

		for (MethodInformation method : methodsList.methods) {
			if (methodMap.containsKey(method.methodName)) {
				methodMap.get(method.methodName).add(method);
			} else {
				ArrayList<MethodInformation> t = new ArrayList<MethodInformation>();
				t.add(method);
				methodMap.put(method.methodName, t);
			}
		}

		println("[+] Applying function signatures...");
		for (String m : methodMap.keySet()) {
			ArrayList<MethodInformation> methodList = methodMap.get(m);

			if (methodList.size() == 1) {
				MethodInformation method = methodList.get(0);
				String methodName = this.generateNativeMethodName(method, false);

				if (functions.containsKey(methodName)) {
					Function f = functions.get(methodName);
					this.applyFunctionSignature(methodName, method, f);
				}
			} else {
				for (MethodInformation method : methodList) {
					String methodName = this.generateNativeMethodName(method, true);
					if (functions.containsKey(methodName)) {
						Function f = functions.get(methodName);
						this.applyFunctionSignature(methodName, method, f);
					}
				}
			}
		}
	}

	private void applyFunctionSignature(String methodName, MethodInformation method, Function f)
			throws InvalidInputException, DuplicateNameException {

		Parameter[] params = new Parameter[method.argumentTypes.size() + 2]; // + 2 to accomodate env and thiz

		params[0] = new ParameterImpl("env", this.manager.getDataType("/jni_all.h/JNIEnv *"), this.currentProgram,
				SourceType.USER_DEFINED);

		if (method.isStatic) {
			params[1] = new ParameterImpl("thiz", this.manager.getDataType("/jni_all.h/jclass"), this.currentProgram,
					SourceType.USER_DEFINED);
		} else {
			params[1] = new ParameterImpl("thiz", this.manager.getDataType("/jni_all.h/jobject"), this.currentProgram,
					SourceType.USER_DEFINED);
		}

		for (int i = 0; i < method.argumentTypes.size(); i++) {
			String argType = method.argumentTypes.get(i);

			params[i + 2] = new ParameterImpl("a" + String.valueOf(i),
					this.manager.getDataType("/jni_all.h/" + argType), this.currentProgram, SourceType.USER_DEFINED);
		}

		Parameter returnType = new ReturnParameterImpl(this.manager.getDataType("/jni_all.h/" + method.returnType),
				this.currentProgram);

		f.updateFunction(null, returnType, Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true,
				SourceType.USER_DEFINED, params);

	}

	private void applyJNIOnLoadSignature(Function function) throws DuplicateNameException, InvalidInputException {
		println("Applying signature to " + function.getName());

		Parameter[] params = new Parameter[2];

		params[0] = new ParameterImpl("vm", this.manager.getDataType("/jni_all.h/JavaVM *"), this.currentProgram,
				SourceType.USER_DEFINED);

		params[1] = new ParameterImpl("reserved", this.manager.getDataType("/void *"), this.currentProgram,
				SourceType.USER_DEFINED);

		Parameter returnType;
		if (function.getName().equals("JNI_OnLoad")) {
			returnType = new ReturnParameterImpl(this.manager.getDataType("/jni_all.h/jint"), this.currentProgram);
		} else {
			returnType = new ReturnParameterImpl(this.manager.getDataType("/void"), this.currentProgram);
		}

		function.updateFunction(null, returnType, Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true,
				SourceType.USER_DEFINED, params);
	}

	private String generateNativeMethodName(MethodInformation methodInfo, boolean isOverloaded) {
		String methodName = methodInfo.methodName;

		methodName = methodName.replaceAll("_", "_1");
		methodName = this.mangleUnicode(methodName);

		String[] methodNameSplit = methodName.toString().split("\\.");
		methodName = "Java_" + String.join("_", methodNameSplit);

		if (isOverloaded) {
			String argumentSignature = methodInfo.argumentSignature;

			argumentSignature = argumentSignature.replaceAll("_", "_1");
			argumentSignature = argumentSignature.replaceAll(";", "_2");
			argumentSignature = argumentSignature.replaceAll("\\[", "_3");
			argumentSignature = this.mangleUnicode(argumentSignature);
			argumentSignature = argumentSignature.replaceAll("/", "_");

			methodName = methodName + "__" + argumentSignature;
		}

		return methodName;
	}

	private String mangleUnicode(String s) {
		StringBuilder sb = new StringBuilder();

		for (int offset = 0; offset < s.length();) {
			int codepoint = s.codePointAt(offset);

			// If codepoint is ASCII:
			if (codepoint >= 0 && codepoint <= 127) {
				sb.append((char) codepoint);
			} else {
				// If unicode, convert e.g. character \u8c22 to _08c22
				sb.append("_0");
				sb.append(String.format("%4s", Integer.toHexString(codepoint)).replace(' ', '0'));
			}

			offset += Character.charCount(codepoint);
		}

		return sb.toString();
	}
}
