/* ###
 * IP: Apache License 2.0 with LLVM Exceptions
 */
/* ----------------------------------------------------------------------------
 * This file was automatically generated by SWIG (http://www.swig.org).
 * Version 4.0.1
 *
 * Do not make changes to this file unless you know what you are doing--modify
 * the SWIG interface file instead.
 * ----------------------------------------------------------------------------- */

package SWIG;

public final class FormatterMatchType {
  public final static FormatterMatchType eFormatterMatchExact = new FormatterMatchType("eFormatterMatchExact");
  public final static FormatterMatchType eFormatterMatchRegex = new FormatterMatchType("eFormatterMatchRegex");
  public final static FormatterMatchType eFormatterMatchCallback = new FormatterMatchType("eFormatterMatchCallback");
  public final static FormatterMatchType eLastFormatterMatchType = new FormatterMatchType("eLastFormatterMatchType", lldbJNI.eLastFormatterMatchType_get());

  public final int swigValue() {
    return swigValue;
  }

  public String toString() {
    return swigName;
  }

  public static FormatterMatchType swigToEnum(int swigValue) {
    if (swigValue < swigValues.length && swigValue >= 0 && swigValues[swigValue].swigValue == swigValue)
      return swigValues[swigValue];
    for (int i = 0; i < swigValues.length; i++)
      if (swigValues[i].swigValue == swigValue)
        return swigValues[i];
    throw new IllegalArgumentException("No enum " + FormatterMatchType.class + " with value " + swigValue);
  }

  private FormatterMatchType(String swigName) {
    this.swigName = swigName;
    this.swigValue = swigNext++;
  }

  private FormatterMatchType(String swigName, int swigValue) {
    this.swigName = swigName;
    this.swigValue = swigValue;
    swigNext = swigValue+1;
  }

  private FormatterMatchType(String swigName, FormatterMatchType swigEnum) {
    this.swigName = swigName;
    this.swigValue = swigEnum.swigValue;
    swigNext = this.swigValue+1;
  }

  private static FormatterMatchType[] swigValues = { eFormatterMatchExact, eFormatterMatchRegex, eFormatterMatchCallback, eLastFormatterMatchType };
  private static int swigNext = 0;
  private final int swigValue;
  private final String swigName;
}

