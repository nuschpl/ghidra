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


public class SBUnixSignals {
  private transient long swigCPtr;
  protected transient boolean swigCMemOwn;

  protected SBUnixSignals(long cPtr, boolean cMemoryOwn) {
    swigCMemOwn = cMemoryOwn;
    swigCPtr = cPtr;
  }

  protected static long getCPtr(SBUnixSignals obj) {
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
        lldbJNI.delete_SBUnixSignals(swigCPtr);
      }
      swigCPtr = 0;
    }
  }

  public SBUnixSignals() {
    this(lldbJNI.new_SBUnixSignals__SWIG_0(), true);
  }

  public SBUnixSignals(SBUnixSignals rhs) {
    this(lldbJNI.new_SBUnixSignals__SWIG_1(SBUnixSignals.getCPtr(rhs), rhs), true);
  }

  public void Clear() {
    lldbJNI.SBUnixSignals_Clear(swigCPtr, this);
  }

  public boolean IsValid() {
    return lldbJNI.SBUnixSignals_IsValid(swigCPtr, this);
  }

  public String GetSignalAsCString(int signo) {
    return lldbJNI.SBUnixSignals_GetSignalAsCString(swigCPtr, this, signo);
  }

  public int GetSignalNumberFromName(String name) {
    return lldbJNI.SBUnixSignals_GetSignalNumberFromName(swigCPtr, this, name);
  }

  public boolean GetShouldSuppress(int signo) {
    return lldbJNI.SBUnixSignals_GetShouldSuppress(swigCPtr, this, signo);
  }

  public boolean SetShouldSuppress(int signo, boolean value) {
    return lldbJNI.SBUnixSignals_SetShouldSuppress(swigCPtr, this, signo, value);
  }

  public boolean GetShouldStop(int signo) {
    return lldbJNI.SBUnixSignals_GetShouldStop(swigCPtr, this, signo);
  }

  public boolean SetShouldStop(int signo, boolean value) {
    return lldbJNI.SBUnixSignals_SetShouldStop(swigCPtr, this, signo, value);
  }

  public boolean GetShouldNotify(int signo) {
    return lldbJNI.SBUnixSignals_GetShouldNotify(swigCPtr, this, signo);
  }

  public boolean SetShouldNotify(int signo, boolean value) {
    return lldbJNI.SBUnixSignals_SetShouldNotify(swigCPtr, this, signo, value);
  }

  public int GetNumSignals() {
    return lldbJNI.SBUnixSignals_GetNumSignals(swigCPtr, this);
  }

  public int GetSignalAtIndex(int index) {
    return lldbJNI.SBUnixSignals_GetSignalAtIndex(swigCPtr, this, index);
  }

}
