package me.ayrx.jnianalyzer;

import java.util.ArrayList;

public class MethodInformation {
	public String methodName;
	public String argumentSignature;
	public ArrayList<String> argumentTypes;
	public String returnType;
	public boolean isStatic;

	public MethodInformation(String methodName, String argumentSignature, ArrayList<String> argumentTypes,
			String returnType, boolean isStatic) {
		this.methodName = methodName;
		this.argumentSignature = argumentSignature;
		this.argumentTypes = argumentTypes;
		this.returnType = returnType;
		this.isStatic = isStatic;
	}

}
