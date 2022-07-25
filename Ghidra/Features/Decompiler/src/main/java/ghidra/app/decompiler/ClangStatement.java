/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * Created on Jun 12, 2003
 *
 * To change the template for this generated file go to
 * Window>Preferences>Java>Code Generation>Code and Comments
 */
package ghidra.app.decompiler;

import ghidra.program.model.pcode.*;

/**
 * 
 *
 * A C code statement. What typically appears between the ';' '{' and '}' characters.
 * A statement must have a pcode operation associated with it. In the case of conditional
 * flow control operations, there are usually two lines associated with the statement one
 * containing the '{' and one containing '}'. The one containing the actual conditional branch
 * is considered a C statement, while the other one is just considered a blank line.
 * I.e.
 * 	if (expression) {
 * is a C statement, while the line containing the closing '}' by itself is considered blank
 */
public class ClangStatement extends ClangTokenGroup {
	private PcodeOp op;		// Root op of C-statement

	public ClangStatement(ClangNode par) {
		super(par);
		op = null;
	}

	public PcodeOp getPcodeOp() {
		return op;
	}

	@Override
	public void decode(Decoder decoder, PcodeFactory pfactory) throws PcodeXMLException {
		for (;;) {
			int attribId = decoder.getNextAttributeId();
			if (attribId == 0) {
				break;
			}
			if (attribId == AttributeId.ATTRIB_OPREF.id()) {
				int refid = (int) decoder.readUnsignedInteger();
				op = pfactory.getOpRef(refid);
				break;
			}
		}
		super.decode(decoder, pfactory);
	}
}
