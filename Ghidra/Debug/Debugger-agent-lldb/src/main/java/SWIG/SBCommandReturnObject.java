/* ###
 * IP: Apache License 2.0 with LLVM Exceptions
 */
package SWIG;


/* ----------------------------------------------------------------------------
 * This file was automatically generated by SWIG (http://www.swig.org).
 * Version 4.0.2
 *
 * Do not make changes to this file unless you know what you are doing--modify
 * the SWIG interface file instead.
 * ----------------------------------------------------------------------------- */


public class SBCommandReturnObject {
  private transient long swigCPtr;
  protected transient boolean swigCMemOwn;

  protected SBCommandReturnObject(long cPtr, boolean cMemoryOwn) {
    swigCMemOwn = cMemoryOwn;
    swigCPtr = cPtr;
  }

  protected static long getCPtr(SBCommandReturnObject obj) {
    return (obj == null) ? 0 : obj.swigCPtr;
  }

  @SuppressWarnings("deprecation")
  protected void finalize() {
    delete();
  }

  public synchronized void delete() {
    if (swigCPtr != 0) {
      if (swigCMemOwn) {
        swigCMemOwn = false;
        lldbJNI.delete_SBCommandReturnObject(swigCPtr);
      }
      swigCPtr = 0;
    }
  }

  public SBCommandReturnObject() {
    this(lldbJNI.new_SBCommandReturnObject__SWIG_0(), true);
  }

  public SBCommandReturnObject(SBCommandReturnObject rhs) {
    this(lldbJNI.new_SBCommandReturnObject__SWIG_1(SBCommandReturnObject.getCPtr(rhs), rhs), true);
  }

  public boolean IsValid() {
    return lldbJNI.SBCommandReturnObject_IsValid(swigCPtr, this);
  }

  public String GetOutput() {
    return lldbJNI.SBCommandReturnObject_GetOutput__SWIG_0(swigCPtr, this);
  }

  public String GetError() {
    return lldbJNI.SBCommandReturnObject_GetError__SWIG_0(swigCPtr, this);
  }

  public long GetOutputSize() {
    return lldbJNI.SBCommandReturnObject_GetOutputSize(swigCPtr, this);
  }

  public long GetErrorSize() {
    return lldbJNI.SBCommandReturnObject_GetErrorSize(swigCPtr, this);
  }

  public String GetOutput(boolean only_if_no_immediate) {
    return lldbJNI.SBCommandReturnObject_GetOutput__SWIG_1(swigCPtr, this, only_if_no_immediate);
  }

  public String GetError(boolean if_no_immediate) {
    return lldbJNI.SBCommandReturnObject_GetError__SWIG_1(swigCPtr, this, if_no_immediate);
  }

  public long PutOutput(SBFile file) {
    return lldbJNI.SBCommandReturnObject_PutOutput__SWIG_0(swigCPtr, this, SBFile.getCPtr(file), file);
  }

  public long PutError(SBFile file) {
    return lldbJNI.SBCommandReturnObject_PutError__SWIG_0(swigCPtr, this, SBFile.getCPtr(file), file);
  }

  public long PutOutput(SWIGTYPE_p_std__shared_ptrT_lldb_private__File_t BORROWED) {
    return lldbJNI.SBCommandReturnObject_PutOutput__SWIG_1(swigCPtr, this, SWIGTYPE_p_std__shared_ptrT_lldb_private__File_t.getCPtr(BORROWED));
  }

  public long PutError(SWIGTYPE_p_std__shared_ptrT_lldb_private__File_t BORROWED) {
    return lldbJNI.SBCommandReturnObject_PutError__SWIG_1(swigCPtr, this, SWIGTYPE_p_std__shared_ptrT_lldb_private__File_t.getCPtr(BORROWED));
  }

  public void Clear() {
    lldbJNI.SBCommandReturnObject_Clear(swigCPtr, this);
  }

  public void SetStatus(ReturnStatus status) {
    lldbJNI.SBCommandReturnObject_SetStatus(swigCPtr, this, status.swigValue());
  }

  public void SetError(SBError error, String fallback_error_cstr) {
    lldbJNI.SBCommandReturnObject_SetError__SWIG_0(swigCPtr, this, SBError.getCPtr(error), error, fallback_error_cstr);
  }

  public void SetError(SBError error) {
    lldbJNI.SBCommandReturnObject_SetError__SWIG_1(swigCPtr, this, SBError.getCPtr(error), error);
  }

  public void SetError(String error_cstr) {
    lldbJNI.SBCommandReturnObject_SetError__SWIG_2(swigCPtr, this, error_cstr);
  }

  public ReturnStatus GetStatus() {
    return ReturnStatus.swigToEnum(lldbJNI.SBCommandReturnObject_GetStatus(swigCPtr, this));
  }

  public boolean Succeeded() {
    return lldbJNI.SBCommandReturnObject_Succeeded(swigCPtr, this);
  }

  public boolean HasResult() {
    return lldbJNI.SBCommandReturnObject_HasResult(swigCPtr, this);
  }

  public void AppendMessage(String message) {
    lldbJNI.SBCommandReturnObject_AppendMessage(swigCPtr, this, message);
  }

  public void AppendWarning(String message) {
    lldbJNI.SBCommandReturnObject_AppendWarning(swigCPtr, this, message);
  }

  public boolean GetDescription(SBStream description) {
    return lldbJNI.SBCommandReturnObject_GetDescription(swigCPtr, this, SBStream.getCPtr(description), description);
  }

  public void SetImmediateOutputFile(SBFile file) {
    lldbJNI.SBCommandReturnObject_SetImmediateOutputFile__SWIG_0(swigCPtr, this, SBFile.getCPtr(file), file);
  }

  public void SetImmediateErrorFile(SBFile file) {
    lldbJNI.SBCommandReturnObject_SetImmediateErrorFile__SWIG_0(swigCPtr, this, SBFile.getCPtr(file), file);
  }

  public void SetImmediateOutputFile(SWIGTYPE_p_std__shared_ptrT_lldb_private__File_t BORROWED) {
    lldbJNI.SBCommandReturnObject_SetImmediateOutputFile__SWIG_1(swigCPtr, this, SWIGTYPE_p_std__shared_ptrT_lldb_private__File_t.getCPtr(BORROWED));
  }

  public void SetImmediateErrorFile(SWIGTYPE_p_std__shared_ptrT_lldb_private__File_t BORROWED) {
    lldbJNI.SBCommandReturnObject_SetImmediateErrorFile__SWIG_1(swigCPtr, this, SWIGTYPE_p_std__shared_ptrT_lldb_private__File_t.getCPtr(BORROWED));
  }

  public String __str__() {
    return lldbJNI.SBCommandReturnObject___str__(swigCPtr, this);
  }

  public void SetImmediateOutputFile(SWIGTYPE_p_std__shared_ptrT_lldb_private__File_t BORROWED, boolean transfer_ownership) {
    lldbJNI.SBCommandReturnObject_SetImmediateOutputFile__SWIG_2(swigCPtr, this, SWIGTYPE_p_std__shared_ptrT_lldb_private__File_t.getCPtr(BORROWED), transfer_ownership);
  }

  public void SetImmediateErrorFile(SWIGTYPE_p_std__shared_ptrT_lldb_private__File_t BORROWED, boolean transfer_ownership) {
    lldbJNI.SBCommandReturnObject_SetImmediateErrorFile__SWIG_2(swigCPtr, this, SWIGTYPE_p_std__shared_ptrT_lldb_private__File_t.getCPtr(BORROWED), transfer_ownership);
  }

  public void PutCString(String string, int len) {
    lldbJNI.SBCommandReturnObject_PutCString(swigCPtr, this, string, len);
  }

  public void Print(String str) {
    lldbJNI.SBCommandReturnObject_Print(swigCPtr, this, str);
  }

}
