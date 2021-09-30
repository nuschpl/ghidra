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


public class SBTypeSummary {
  private transient long swigCPtr;
  protected transient boolean swigCMemOwn;

  protected SBTypeSummary(long cPtr, boolean cMemoryOwn) {
    swigCMemOwn = cMemoryOwn;
    swigCPtr = cPtr;
  }

  protected static long getCPtr(SBTypeSummary obj) {
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
        lldbJNI.delete_SBTypeSummary(swigCPtr);
      }
      swigCPtr = 0;
    }
  }

  public SBTypeSummary() {
    this(lldbJNI.new_SBTypeSummary__SWIG_0(), true);
  }

  public static SBTypeSummary CreateWithSummaryString(String data, long options) {
    return new SBTypeSummary(lldbJNI.SBTypeSummary_CreateWithSummaryString__SWIG_0(data, options), true);
  }

  public static SBTypeSummary CreateWithSummaryString(String data) {
    return new SBTypeSummary(lldbJNI.SBTypeSummary_CreateWithSummaryString__SWIG_1(data), true);
  }

  public static SBTypeSummary CreateWithFunctionName(String data, long options) {
    return new SBTypeSummary(lldbJNI.SBTypeSummary_CreateWithFunctionName__SWIG_0(data, options), true);
  }

  public static SBTypeSummary CreateWithFunctionName(String data) {
    return new SBTypeSummary(lldbJNI.SBTypeSummary_CreateWithFunctionName__SWIG_1(data), true);
  }

  public static SBTypeSummary CreateWithScriptCode(String data, long options) {
    return new SBTypeSummary(lldbJNI.SBTypeSummary_CreateWithScriptCode__SWIG_0(data, options), true);
  }

  public static SBTypeSummary CreateWithScriptCode(String data) {
    return new SBTypeSummary(lldbJNI.SBTypeSummary_CreateWithScriptCode__SWIG_1(data), true);
  }

  public SBTypeSummary(SBTypeSummary rhs) {
    this(lldbJNI.new_SBTypeSummary__SWIG_1(SBTypeSummary.getCPtr(rhs), rhs), true);
  }

  public boolean IsValid() {
    return lldbJNI.SBTypeSummary_IsValid(swigCPtr, this);
  }

  public boolean IsEqualTo(SBTypeSummary rhs) {
    return lldbJNI.SBTypeSummary_IsEqualTo(swigCPtr, this, SBTypeSummary.getCPtr(rhs), rhs);
  }

  public boolean IsFunctionCode() {
    return lldbJNI.SBTypeSummary_IsFunctionCode(swigCPtr, this);
  }

  public boolean IsFunctionName() {
    return lldbJNI.SBTypeSummary_IsFunctionName(swigCPtr, this);
  }

  public boolean IsSummaryString() {
    return lldbJNI.SBTypeSummary_IsSummaryString(swigCPtr, this);
  }

  public String GetData() {
    return lldbJNI.SBTypeSummary_GetData(swigCPtr, this);
  }

  public void SetSummaryString(String data) {
    lldbJNI.SBTypeSummary_SetSummaryString(swigCPtr, this, data);
  }

  public void SetFunctionName(String data) {
    lldbJNI.SBTypeSummary_SetFunctionName(swigCPtr, this, data);
  }

  public void SetFunctionCode(String data) {
    lldbJNI.SBTypeSummary_SetFunctionCode(swigCPtr, this, data);
  }

  public long GetOptions() {
    return lldbJNI.SBTypeSummary_GetOptions(swigCPtr, this);
  }

  public void SetOptions(long arg0) {
    lldbJNI.SBTypeSummary_SetOptions(swigCPtr, this, arg0);
  }

  public boolean GetDescription(SBStream description, DescriptionLevel description_level) {
    return lldbJNI.SBTypeSummary_GetDescription(swigCPtr, this, SBStream.getCPtr(description), description, description_level.swigValue());
  }

  public String __str__() {
    return lldbJNI.SBTypeSummary___str__(swigCPtr, this);
  }

}
