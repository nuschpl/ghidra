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


public class SBTraceOptions {
  private transient long swigCPtr;
  protected transient boolean swigCMemOwn;

  protected SBTraceOptions(long cPtr, boolean cMemoryOwn) {
    swigCMemOwn = cMemoryOwn;
    swigCPtr = cPtr;
  }

  protected static long getCPtr(SBTraceOptions obj) {
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
        lldbJNI.delete_SBTraceOptions(swigCPtr);
      }
      swigCPtr = 0;
    }
  }

  public SBTraceOptions() {
    this(lldbJNI.new_SBTraceOptions(), true);
  }

  public TraceType getType() {
    return TraceType.swigToEnum(lldbJNI.SBTraceOptions_getType(swigCPtr, this));
  }

  public java.math.BigInteger getTraceBufferSize() {
    return lldbJNI.SBTraceOptions_getTraceBufferSize(swigCPtr, this);
  }

  public SBStructuredData getTraceParams(SBError error) {
    return new SBStructuredData(lldbJNI.SBTraceOptions_getTraceParams(swigCPtr, this, SBError.getCPtr(error), error), true);
  }

  public java.math.BigInteger getMetaDataBufferSize() {
    return lldbJNI.SBTraceOptions_getMetaDataBufferSize(swigCPtr, this);
  }

  public void setTraceParams(SBStructuredData params) {
    lldbJNI.SBTraceOptions_setTraceParams(swigCPtr, this, SBStructuredData.getCPtr(params), params);
  }

  public void setType(TraceType type) {
    lldbJNI.SBTraceOptions_setType(swigCPtr, this, type.swigValue());
  }

  public void setTraceBufferSize(java.math.BigInteger size) {
    lldbJNI.SBTraceOptions_setTraceBufferSize(swigCPtr, this, size);
  }

  public void setMetaDataBufferSize(java.math.BigInteger size) {
    lldbJNI.SBTraceOptions_setMetaDataBufferSize(swigCPtr, this, size);
  }

  public void setThreadID(java.math.BigInteger thread_id) {
    lldbJNI.SBTraceOptions_setThreadID(swigCPtr, this, thread_id);
  }

  public java.math.BigInteger getThreadID() {
    return lldbJNI.SBTraceOptions_getThreadID(swigCPtr, this);
  }

  public boolean IsValid() {
    return lldbJNI.SBTraceOptions_IsValid(swigCPtr, this);
  }

}
