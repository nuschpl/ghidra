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
package ghidra.program.model.pcode;

import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.ParamEntry;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

public class MappedSymbol extends HighSymbol {

	private VariableStorage storage;
	private int slot;		// parameter slot, -1 for non-parameter

	public MappedSymbol(HighFunction func) {	// For use with restoreXML
		super(func);
	}

	public MappedSymbol(long uniqueId, String name, DataType dt, VariableStorage store,
			Address pcaddr,
			HighFunction func, int slot) {
		super(uniqueId, name, dt, store.size(), pcaddr, func);
		if (store.size() != dt.getLength()) {
			if (ParamEntry.getMetatype(dt) != ParamEntry.TYPE_FLOAT) {
				throw new IllegalArgumentException("Specified size does not match storage size");
			}
		}
		this.storage = store;
		this.slot = slot;
	}

	@Override
	public VariableStorage getStorage() {
		return storage;
	}

	@Override
	public boolean isParameter() {
		return slot >= 0;
	}

	public int getSlot() {
		return slot;
	}

	@Override
	public String buildXML() {
		if (storage.getMinAddress() == null) {
			return ""; // skip unassigned/bad variable
		}
		StringBuilder res = new StringBuilder();
		int cat = isParameter() ? 0 : -1;
		String sym = buildSymbolXML(function.getDataTypeManager(), getId(), name, type, size,
									isTypeLocked(), isNameLocked(), false, false, cat, slot);
		int logicalsize = 0; // Assume datatype size and storage size are the same
		if ((type != null) && (type.getLength() != storage.size()))
		 {
			logicalsize = type.getLength(); // Force a logicalsize
		}
		String addrRes = Varnode.buildXMLAddress(storage.getVarnodes(), logicalsize);
		buildMapSymXML(res, addrRes, getPCAddress(), sym);
		return res.toString();
	}

	@Override
	public void restoreXML(XmlPullParser parser) throws PcodeXMLException {
		XmlElement symel = parser.start("symbol");
		restoreSymbolXML(symel);
		slot = -1;
		int cat = -1;
		if (symel.hasAttribute("cat")) {
			cat = SpecXmlUtils.decodeInt(symel.getAttribute("cat"));
			if (cat == 0) {
				slot = SpecXmlUtils.decodeInt(symel.getAttribute("index"));
			}
		}
		type = function.getDataTypeManager().readXMLDataType(parser);
		parser.end(symel);

		if (slot >= 0 && name.startsWith("$$undef")) {
			// use default parameter name
			name = "param_" + Integer.toString(slot + 1);
		}

		restoreEntryXML(parser);
		while (parser.peek().isStart()) {
			parser.discardSubTree();
		}
	}

	@Override
	protected void restoreEntryXML(XmlPullParser parser) throws PcodeXMLException {
		Program program = function.getFunction().getProgram();
		AddressFactory addrFactory = function.getAddressFactory();

		XmlElement addrel = parser.start("addr");
		int sz = type.getLength();
		if (sz == 0) {
			throw new PcodeXMLException("Invalid symbol 0-sized data-type: " + type.getName());
		}
		try {
			Address varAddr = Varnode.readXMLAddress(addrel, addrFactory);
			AddressSpace spc = varAddr.getAddressSpace();
			if ((spc == null) || (spc.getType() != AddressSpace.TYPE_VARIABLE)) {
				storage = new VariableStorage(program, varAddr, sz);
			}
			else {
				storage = function.readXMLVarnodePieces(addrel, varAddr);
			}
		}
		catch (InvalidInputException e) {
			throw new PcodeXMLException("Invalid storage: " + e.getMessage());
		}
		size = storage.size();
		parser.end(addrel);

		pcaddr = parseRangeList(parser);
	}

	public static String buildSymbolXML(PcodeDataTypeManager dtmanage, long uniqueId, String nm,
										DataType dt, int length, boolean tl, boolean nl, boolean ro,
										boolean isVolatile, int cat, int slot) {
		StringBuilder res = new StringBuilder();
		res.append("<symbol");
		if ((uniqueId >> 56) == (ID_BASE >> 56)) {
			uniqueId = 0;			// Don't send down internal ids
		}
		if (uniqueId != 0) {
			SpecXmlUtils.encodeUnsignedIntegerAttribute(res, "id", uniqueId);
		}
		SpecXmlUtils.xmlEscapeAttribute(res, "name", nm);
		SpecXmlUtils.encodeBooleanAttribute(res, "typelock", tl);
		SpecXmlUtils.encodeBooleanAttribute(res, "namelock", nl);
		SpecXmlUtils.encodeBooleanAttribute(res, "readonly", ro);
		if (isVolatile) {
			SpecXmlUtils.encodeBooleanAttribute(res, "volatile", true);
		}
		SpecXmlUtils.encodeSignedIntegerAttribute(res, "cat", cat);
		if (slot >= 0) {
			SpecXmlUtils.encodeSignedIntegerAttribute(res, "index", slot);
		}
		res.append(">\n");
		res.append(dtmanage.buildTypeRef(dt, length));
		res.append("</symbol>\n");
		return res.toString();
	}
}
