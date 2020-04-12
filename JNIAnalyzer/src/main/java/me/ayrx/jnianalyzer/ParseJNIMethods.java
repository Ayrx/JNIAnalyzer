package me.ayrx.jnianalyzer;

import java.io.File;
import java.util.ArrayList;

import jadx.api.JadxArgs;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;
import jadx.api.JavaMethod;
import jadx.core.dex.instructions.args.ArgType;

public class ParseJNIMethods {

	public static ArrayList<MethodInformation> parse(File apk) {
		JadxArgs jadxArgs = new JadxArgs();
		jadxArgs.setDebugInfo(false);
		jadxArgs.getInputFiles().add(apk);
		JadxDecompiler jadx = new JadxDecompiler(jadxArgs);
		jadx.load();

		ArrayList<JavaMethod> nativeMethods = new ArrayList<>();

		for (JavaClass klass : jadx.getClasses()) {
			for (JavaMethod method : klass.getMethods()) {
				if (method.getAccessFlags().isNative()) {
					nativeMethods.add(method);
				}
			}
		}

		ArrayList<MethodInformation> methodsList = new ArrayList<>();

		for (JavaMethod method : nativeMethods) {
			ArrayList<String> methodType = new ArrayList<>();
			StringBuilder argumentSignatureBuilder = new StringBuilder();

			for (ArgType argument : method.getArguments()) {
				methodType.add(parseArgumentType(argument));
				argumentSignatureBuilder.append(parseArgumentSignature(argument));
			}

			String returnType = parseArgumentType(method.getReturnType());

			boolean isStatic = method.getAccessFlags().isStatic();

			String argumentSignature = argumentSignatureBuilder.toString();

			MethodInformation methodInfo = new MethodInformation(method.getFullName(), argumentSignature, methodType,
					returnType, isStatic);
			methodsList.add(methodInfo);
		}

		return methodsList;
	}

	private static String parseArgumentSignature(ArgType argument) {
		String type;
		if (argument.isPrimitive()) {
			type = convertPrimitiveSignature(argument);
		} else if (argument.isArray()) {
			type = "[" + parseArgumentSignature(argument.getArrayRootElement());
		} else {
			type = "L" + argument.getObject().replaceAll("\\.", "/") + ";";
		}
		return type;
	}

	private static String parseArgumentType(ArgType argument) {
		String type;
		if (argument.isPrimitive()) {
			type = convertPrimitive(argument);
		} else if (argument.isArray()) {
			type = convertArray(argument);
		} else if (argument.toString().equals("Java.lang.String")) {
			type = "jstring";
		} else {
			type = "jobject";
		}
		return type;
	}

	private static String convertArray(ArgType type) {
		String ret;

		switch (type.getArrayRootElement().getPrimitiveType().getLongName()) {
		case "boolean":
			ret = "jbooleanArray";
			break;
		case "byte":
			ret = "jbyteArray";
			break;
		case "char":
			ret = "jcharArray";
			break;
		case "short":
			ret = "jshortArray";
			break;
		case "int":
			ret = "jintArray";
			break;
		case "long":
			ret = "jlongArray";
			break;
		case "float":
			ret = "jfloatArray";
			break;
		case "double":
			ret = "jdoubleArray";
			break;
		default:
			ret = "jobjectArray";
			break;
		}

		return ret;
	}

	private static String convertPrimitive(ArgType type) {
		String ret;

		switch (type.getPrimitiveType().getLongName()) {
		case "boolean":
			ret = "jboolean";
			break;
		case "byte":
			ret = "jbyte";
			break;
		case "char":
			ret = "jchar";
			break;
		case "short":
			ret = "jshort";
			break;
		case "int":
			ret = "jint";
			break;
		case "long":
			ret = "jlong";
			break;
		case "float":
			ret = "jfloat";
			break;
		case "double":
			ret = "jdouble";
			break;
		case "void":
			ret = "void";
			break;
		default:
			ret = null;
			break;
		}

		return ret;
	}

	private static String convertPrimitiveSignature(ArgType type) {
		String ret;

		switch (type.getPrimitiveType().getLongName()) {
		case "boolean":
			ret = "Z";
			break;
		case "byte":
			ret = "B";
			break;
		case "char":
			ret = "C";
			break;
		case "short":
			ret = "S";
			break;
		case "int":
			ret = "I";
			break;
		case "long":
			ret = "J";
			break;
		case "float":
			ret = "F";
			break;
		case "double":
			ret = "D";
			break;
		case "void":
			ret = "V";
			break;
		default:
			ret = null;
			break;
		}

		return ret;
	}

}
