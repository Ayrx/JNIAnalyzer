//Applies the standard JNI parameter types to the `JNI_OnLoad` function
//as well as all functions starting with `Java_`.
//
//`Java_` functions with less than two parameters are left untouched.
//The appropriate function parameters should be applied manually to them.
//@author Ayrx
//@category JNI
//@keybinding 
//@menupath 
//@toolbar 

import generic.jar.ResourceFile;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;

import ghidra.app.plugin.core.datamgr.archive.Archive;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.DataTypeManagerService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.*;
import ghidra.util.exception.*;
import ghidra.app.plugin.core.datamgr.archive.DuplicateIdException;

public class JNIAnalyzer extends GhidraScript {

	DataTypeManager manager;
	
    public void run() throws Exception {
    	this.manager = this.getDataTypeManageFromArchiveFile();
    	println("[+] Applying JNI function signature...");
    	

    	ArrayList<Function> skippedFunctions = new ArrayList();
    	Function function = this.getFirstFunction();
    	while (function != null) {
    		if (function.getName().startsWith("Java_")) {
    			if (function.getParameterCount() >= 2) {
    				this.applyJNIFunctionSignature(function);
    			} else {
    				skippedFunctions.add(function);    			}
    		} 
    		
    		if (function.getName().equals("JNI_OnLoad")) {
    			this.applyJNIOnLoadSignature(function);
    		}
    		
    		function = this.getFunctionAfter(function);
    	}	
    	
    	println("Skipped function:");
    	for (Function f : skippedFunctions) {
    		println(f.getName());
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
    	File jniArchiveFile = new File(
    		this.getSourceFile().getParentFile().getAbsolutePath(),
			"jni_all.gdt"
		);
    	Archive jniArchive = service.openArchive(jniArchiveFile, false);
    	return jniArchive.getDataTypeManager();
    }
    
    private void applyJNIOnLoadSignature(Function function) throws DuplicateNameException, InvalidInputException {
    	println("Modified " + function.getName());
    	
    	Parameter arg0 = function.getParameter(0);
    	arg0.setName("vm", SourceType.USER_DEFINED);
    	arg0.setDataType(
	    	this.manager.getDataType("/jni_all.h/JavaVM *"),
			SourceType.USER_DEFINED
		);
    }
	    
    private void applyJNIFunctionSignature(Function function) throws DuplicateNameException, InvalidInputException {
    	println("Modified " + function.getName());
    	
    	Parameter arg0 = function.getParameter(0);
    	arg0.setName("env", SourceType.USER_DEFINED);
    	arg0.setDataType(
	    	this.manager.getDataType("/jni_all.h/JNIEnv *"),
			SourceType.USER_DEFINED
		);
    	
    	Parameter arg1 = function.getParameter(1);
    	arg1.setName("thiz", SourceType.USER_DEFINED);
    	arg1.setDataType(
	    	this.manager.getDataType("/jni_all.h/jobject"),
			SourceType.USER_DEFINED
		);    	
    }
}
