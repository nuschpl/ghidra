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

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import org.xml.sax.*;

import ghidra.program.database.symbol.CodeSymbol;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.*;

/**
 *
 *
 * High-level abstraction associated with a low level function made up of assembly instructions.
 * Based on information the decompiler has produced after working on a function.
 */
public class HighFunction extends PcodeSyntaxTree {
	public final static String DECOMPILER_TAG_MAP = "decompiler_tags";
	private Function func; // The traditional function object
	private Language language;
	private CompilerSpec compilerSpec;
	private FunctionPrototype proto; // The high-level prototype associated with the function
	private LocalSymbolMap localSymbols;
	private List<JumpTable> jumpTables;
	private List<DataTypeSymbol> protoOverrides;
	private boolean showNamespace = true;

	/**
	 * @param function  function associated with the higher level function abstraction.
	 * @param language  description of the processor language of the function
	 * @param compilerSpec description of the compiler that produced the function
	 * @param dtManager data type manager
	 * @param showNamespace true signals to print function names with their namespace
	 */
	public HighFunction(Function function, Language language, CompilerSpec compilerSpec,
			PcodeDataTypeManager dtManager, boolean showNamespace) {
		super(function.getProgram().getAddressFactory(), dtManager);
		func = function;
		this.language = language;
		this.compilerSpec = compilerSpec;
		this.showNamespace = showNamespace;
		localSymbols = new LocalSymbolMap(this, "stack");
		proto = new FunctionPrototype(localSymbols, function);
		jumpTables = null;
		protoOverrides = null;
	}

	/**
	 * @return get the associated low level function
	 */
	public Function getFunction() {
		return func;
	}

	/**
	 * @return get the language parser used to disassemble
	 */
	public Language getLanguage() {
		return language;
	}

	public CompilerSpec getCompilerSpec() {
		return compilerSpec;
	}

	/**
	 * @return the function prototype for the function (how things are passed/returned)
	 */
	public FunctionPrototype getFunctionPrototype() {
		return proto;
	}

	/**
	 * @return an array of jump table definitions found for this function decompilation
	 */
	public JumpTable[] getJumpTables() {
		if (jumpTables == null) {
			return new JumpTable[0];
		}
		JumpTable[] res = new JumpTable[jumpTables.size()];
		return jumpTables.toArray(res);
	}

	/**
	 * @return the local variable map describing the defined local variables
	 */
	public LocalSymbolMap getLocalSymbolMap() {
		return localSymbols;
	}

	public HighSymbol getMappedSymbol(Address addr, Address pcaddr) {
		return localSymbols.findLocal(addr, pcaddr);
	}

	@Override
	public HighSymbol getSymbol(long symbolId) {
		return localSymbols.getSymbol(symbolId);
	}

	/**
	 * Populate the information for the HighFunction from the information in the
	 * Function object.
	 *
	 * @param overrideExtrapop is the value to use if extrapop is overridden
	 * @param includeDefaultNames is true if default symbol names should be considered locked
	 * @param doOverride is true if extrapop is overridden
	 */
	public void grabFromFunction(int overrideExtrapop, boolean includeDefaultNames,
			boolean doOverride) {
		localSymbols.grabFromFunction(includeDefaultNames); // Locals must be read first
		proto.grabFromFunction(func, overrideExtrapop, doOverride);
		jumpTables = null;
		protoOverrides = null;
		grabOverrides();
	}

	/**
	 * Check the symbol space for objects that indicate specific overrides to decompiler analysis:
	 *      a) switch flow
	 */
	private void grabOverrides() {
		SymbolTable symtab = func.getProgram().getSymbolTable();
		Namespace space = findOverrideSpace(func);
		if (space == null) {
			return;
		}
		SymbolIterator iter = symtab.getSymbols(space);
		while (iter.hasNext()) {
			Symbol sym = iter.next();
			String nm = sym.getName();
			if (nm.length() < 3) {
				continue;
			}
			nm = nm.substring(0, 3);
			if (nm.equals("jmp")) {
				Object obj = sym.getObject();
				if (obj instanceof Namespace) {
					JumpTable jumpTab = JumpTable.readOverride((Namespace) obj, symtab);
					if (jumpTab != null) {
						if (jumpTables == null) {
							jumpTables = new ArrayList<JumpTable>();
						}
						jumpTables.add(jumpTab);
					}
				}
			}
			else if (nm.equals("prt")) {
				if (sym.getSymbolType() == SymbolType.LABEL) {
					DataTypeSymbol protover = HighFunctionDBUtil.readOverride(sym);
					if (protover != null) {
						if (protoOverrides == null) {
							protoOverrides = new ArrayList<DataTypeSymbol>();
						}
						protoOverrides.add(protover);
					}
				}
			}
		}
	}

	@Override
	public Varnode newVarnode(int sz, Address addr) {
		// translate into function overlay space if possible
		addr = func.getEntryPoint().getAddressSpace().getOverlayAddress(addr);
		return super.newVarnode(sz, addr);
	}

	@Override
	public Varnode newVarnode(int sz, Address addr, int id) {
		// translate into function overlay space if possible
		addr = func.getEntryPoint().getAddressSpace().getOverlayAddress(addr);
		return super.newVarnode(sz, addr, id);
	}

	private void readHighXML(XmlPullParser parser) throws PcodeXMLException {
		XmlElement el = parser.start("high");
		String classstring = el.getAttribute("class");
		int symref = SpecXmlUtils.decodeInt(el.getAttribute("symref"));
		int repref = SpecXmlUtils.decodeInt(el.getAttribute("repref"));
		Varnode rep = getRef(repref);
		if (rep == null) {
			throw new PcodeXMLException("Undefined varnode reference");
		}

		DataType type = null;

		ArrayList<Varnode> vnlist = new ArrayList<Varnode>();
		int sz = -1;
		if (parser.peek().isStart()) {
			type = getDataTypeManager().readXMLDataType(parser);
		}

		if (type == null) {
			throw new PcodeXMLException("Missing <type> for HighVariable");
		}

		// TODO: I'm not sure the decompiler's type size is preserved
		// by the conversion to a GHIDRA type
		sz = type.getLength();

		while (parser.peek().isStart()) {
			Varnode vn = Varnode.readXML(parser, this);
			vnlist.add(vn);
		}
		Varnode[] vnarray = new Varnode[vnlist.size()];
		vnlist.toArray(vnarray);
		// VARDO: does rep varnode size differ from type length ?
		newHigh(symref, type, sz, vnarray, rep, classstring);

		parser.end(el);
	}

	private void readHighlistXML(XmlPullParser parser) throws PcodeXMLException {
		XmlElement el = parser.start("highlist");
		while (parser.peek().isStart()) {
			readHighXML(parser);
		}
		parser.end(el);
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.pcode.PcodeSyntaxTree#readXML(org.jdom.Element)
	 */
	@Override
	public void readXML(XmlPullParser parser) throws PcodeXMLException {
		XmlElement start = parser.start("function");
		String name = start.getAttribute("name");
		if (!func.getName(showNamespace).equals(name)) {
			throw new PcodeXMLException(
				"Function name mismatch: " + func.getName(showNamespace) + " + " + name);
		}
		while (!parser.peek().isEnd()) {
			XmlElement subel = parser.peek();
			if (subel.getName().equals("addr")) {
				subel = parser.start("addr");
				Address addr = Varnode.readXMLAddress(subel, getAddressFactory());
				parser.end(subel);
				addr = func.getEntryPoint().getAddressSpace().getOverlayAddress(addr);
				if (!func.getEntryPoint().equals(addr)) {
					throw new PcodeXMLException("Mismatched address in function tag");
				}
			}
			else if (subel.getName().equals("prototype")) {
				proto.readPrototypeXML(parser, getDataTypeManager());
			}
			else if (subel.getName().equals("localdb")) {
				localSymbols.parseScopeXML(parser);
			}
			else if (subel.getName().equals("ast")) {
				super.readXML(parser);
			}
			else if (subel.getName().equals("highlist")) {
				readHighlistXML(parser);
			}
			else if (subel.getName().equals("jumptablelist")) {
				readJumpTableListXML(parser);
			}
			else if (subel.getName().equals("override")) {
				// Do nothing with override at the moment
				parser.discardSubTree();
			}
			else if (subel.getName().equals("scope")) {
				// This must be a subscope of the local scope
				// Currently this can only hold static variables of the function
				// which ghidra already knows about
				parser.discardSubTree();
			}
			else {
				throw new PcodeXMLException("Unknown tag in function: " + subel.getName());
			}
		}
		parser.end(start);
	}

	/**
	 * Read in the Jump Table list for this function from XML
	 *
	 * @param parser is the XML stream
	 * @throws PcodeXMLException for any format errors
	 */
	private void readJumpTableListXML(XmlPullParser parser) throws PcodeXMLException {
		XmlElement el = parser.start("jumptablelist");
		while (parser.peek().isStart()) {
			JumpTable table = new JumpTable(func.getEntryPoint().getAddressSpace());
			table.restoreXml(parser, getAddressFactory());
			if (!table.isEmpty()) {
				if (jumpTables == null) {
					jumpTables = new ArrayList<JumpTable>();
				}
				jumpTables.add(table);
			}
		}
		parser.end(el);
	}

	private HighVariable newHigh(int symref, DataType tp, int sz, Varnode[] inst, Varnode rep,
			String classstring) throws PcodeXMLException {
		try {
			HighVariable var = null;
			if (classstring.equals("local")) {
				HighSymbol sym = null;
				if (symref != 0) {
					sym = localSymbols.getSymbol(symref);
				}
				if (sym != null) {
					var = sym.getHighVariable();
				}
				if (var == null) {
					if (sym instanceof DynamicSymbol) {
						// establish HighLocal for DynamicSymbol
						var = new HighLocal(tp, rep, inst, sym.getPCAddress(), sym);
						sym.setHighVariable(var);
					}
					else {
						// The variable may be a partial, in which case
						// we treat it as special
						var = new HighOther(tp, rep, inst, getPCAddress(rep), this);
					}
				}
			}
			else if (classstring.equals("constant")) {
				HighSymbol sym = null;
				if (symref != 0) {
					sym = localSymbols.getSymbol(symref);
					if (sym != null) {
						var = sym.getHighVariable();
					}
				}
				if (var == null) {
					if (sym instanceof DynamicSymbol) {
						var = new HighConstant(sym.getName(), tp, rep, getPCAddress(rep),
							(DynamicSymbol) sym);
						sym.setHighVariable(var);
					}
					else {
						var = new HighConstant(null, tp, rep, getPCAddress(rep), this);
					}
				}
			}
			else if (classstring.equals("global")) {
// TODO: should we have access to global symbols
				var = new HighGlobal(null, tp, rep, inst, this);
			}
			else if (classstring.equals("other")) {
// TODO: How do these compare with local ??
				var = new HighOther(tp, rep, inst, getPCAddress(rep), this);
			}
			else {
				throw new PcodeXMLException("Bad class string: " + classstring);
			}
			if (rep.getSize() == var.getSize()) {
				var.attachInstances(inst, rep);
			}
			else { // Make sure varnodes are linked to HighVariable even if not formal instances, why do we do this???
				for (Varnode element : inst) {
					((VarnodeAST) element).setHigh(var);
				}
			}
			var.setHighOnInstances();
			return var;
		}
		catch (InvalidInputException e) {
			throw new PcodeXMLException("Bad storage node", e);
		}
	}

	private Address getPCAddress(Varnode rep) {
		Address pcaddr = null;
		if (!rep.isAddrTied()) {
			pcaddr = rep.getPCAddress();
			if (pcaddr == Address.NO_ADDRESS) {
				try {
					pcaddr = func.getEntryPoint().add(-1);
				}
				catch (AddressOutOfBoundsException e) {
					pcaddr = func.getEntryPoint();
				}
			}
		}
		return pcaddr;
	}

	/**
	 * If a HighVariable consists of more than one (forced) merge group, split out the group
	 * that contains vn as a separate HighVariable. Otherwise just return the original high.
	 * @param high is the HighVariable to split
	 * @param vn is a representative of the merge group to split out
	 * @return a HighVariable containing just the forced merge group of vn
	 * @throws PcodeException if the split can't be performed
	 */
	public HighVariable splitOutMergeGroup(HighVariable high, Varnode vn) throws PcodeException {
		try {
			ArrayList<Varnode> newinst = new ArrayList<Varnode>();
			ArrayList<Varnode> oldinst = new ArrayList<Varnode>();
			short ourgroup = vn.getMergeGroup();
			Varnode[] curinst = high.getInstances();
			for (Varnode curvn : curinst) {
				if (curvn.getMergeGroup() == ourgroup) {
					newinst.add(curvn);
				}
				else {
					oldinst.add(curvn);
				}
			}
			if (oldinst.size() == 0) {
				return high; // Everybody is in the same group
			}
			if (!(high instanceof HighLocal)) {
				throw new PcodeException(
					"Variable " + high.getName() + " is speculatively merged but not a local");
			}
			HighLocal highloc = (HighLocal) high;
			Varnode[] newinstarray = new Varnode[newinst.size()];
			newinst.toArray(newinstarray);
			Varnode[] oldinstarray = new Varnode[oldinst.size()];
			oldinst.toArray(oldinstarray);
			Varnode oldrep = high.getRepresentative();
			HighLocal reslocal;
			HighVariable resremain;
			HighSymbol sym;
			if (oldrep.getMergeGroup() == ourgroup) {
				// Here the requested vn is in the same merge group as the original representative
				// So we keep the original representative and symbol
				if (high instanceof HighParam) {
					return high; // just do ordinary param rename
				}
				vn = oldrep;
				oldrep = oldinstarray[0];
				sym = highloc.getSymbol(); // Keep original symbol with new higher
				reslocal = new HighLocal(highloc.getDataType(), highloc.getRepresentative(), null,
					highloc.getPCAddress(), sym);

				// Shove the remaining varnodes into a HighOther just to be consistent.
				resremain = new HighOther(highloc.getDataType(),
					new Varnode(oldrep.getAddress(), highloc.getSize()), null,
					oldrep.getPCAddress(), this);
			}
			else {
				// Here the requested vn is in a different merge group from the original representative
				// So we create a new symbol based on vn

				// Note that we don't need to distinguish between unique,register,ram etc. and don't
				// need to separate out first use versus mapped use.  When the high local is written
				// to database, these issues will be resolved at that point.
				sym = localSymbols.newMappedSymbol(0, highloc.getName(), highloc.getDataType(),
					new VariableStorage(func.getProgram(), vn), vn.getPCAddress(), -1);
				reslocal = new HighLocal(highloc.getDataType(), vn, null, vn.getPCAddress(), sym);

				resremain = highloc; // Keep remaining varnodes in old high
			}
			sym.setHighVariable(reslocal);
			reslocal.attachInstances(newinstarray, vn);
			for (Varnode element : newinstarray) {
				((VarnodeAST) element).setHigh(reslocal);
			}

			resremain.attachInstances(oldinstarray, oldrep);
			for (Varnode element : oldinstarray) {
				((VarnodeAST) element).setHigh(resremain);
			}
			return reslocal;
		}
		catch (InvalidInputException e) {
			throw new PcodeXMLException("Bad storage node", e);
		}
	}

	/**
	 * Build an XML string that represents all the information about this HighFunction. The
	 * size describes how many bytes starting from the entry point are used by the function, but
	 * this doesn't need to be strictly accurate as it is only used to associate the function with
	 * addresses near its entry point.
	 *
	 * @param entryPoint pass null to use the function entryPoint, pass an address to force an entry point
	 * @param size describes how many bytes the function occupies as code
	 * @return the XML string
	 */
	public String buildFunctionXML(Address entryPoint, int size) {
		// Functions aren't necessarily contiguous with the smallest address being the entry point
		// So size needs to be smaller than size of the contiguous chunk containing the entry point
		StringBuilder resBuf = new StringBuilder();
		resBuf.append("<function");
		SpecXmlUtils.xmlEscapeAttribute(resBuf, "name", func.getName(showNamespace));
		SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "size", size);
		if (func.isInline()) {
			SpecXmlUtils.encodeBooleanAttribute(resBuf, "inline", true);
		}
		if (func.hasNoReturn()) {
			SpecXmlUtils.encodeBooleanAttribute(resBuf, "noreturn", true);
		}
		resBuf.append(">\n");
		if (entryPoint == null) {
			resBuf.append(Varnode.buildXMLAddress(func.getEntryPoint()));
		}
		else {
			resBuf.append(Varnode.buildXMLAddress(entryPoint)); // Address is forced on XML
		}
		resBuf.append(localSymbols.buildLocalDbXML());
		proto.buildPrototypeXML(resBuf, getDataTypeManager());
		if ((jumpTables != null) && (jumpTables.size() > 0)) {
			resBuf.append("<jumptablelist>\n");
			for (int i = 0; i < jumpTables.size(); ++i) {
				jumpTables.get(i).buildXml(resBuf);
			}
			resBuf.append("</jumptablelist>\n");
		}
		boolean hasOverrideTag = ((protoOverrides != null) && (protoOverrides.size() > 0));
		if (hasOverrideTag) {
			resBuf.append("<override>\n");
		}
		if ((protoOverrides != null) && (protoOverrides.size() > 0)) {
			PcodeDataTypeManager dtmanage = getDataTypeManager();
			for (int i = 0; i < protoOverrides.size(); ++i) {
				DataTypeSymbol sym = protoOverrides.get(i);
				Address addr = sym.getAddress();
				FunctionPrototype fproto = new FunctionPrototype(
					(FunctionSignature) sym.getDataType(), compilerSpec, false);
				resBuf.append("<protooverride>\n");
				resBuf.append("<addr");
				Varnode.appendSpaceOffset(resBuf, addr);
				resBuf.append("/>\n");
				fproto.buildPrototypeXML(resBuf, dtmanage);
				resBuf.append("</protooverride>\n");
			}
		}
		if (hasOverrideTag) {
			resBuf.append("</override>\n");
		}
		resBuf.append("</function>\n");
		return resBuf.toString();
	}

	/**
	 * Build the XML representation of only the shell function info not including everything known
	 * about the function.
	 *
	 * @param name name of the function
	 * @param addr address the function is located at
	 *
	 * @return the XML string
	 */
	static public String buildFunctionShellXML(String name, Address addr) {
		StringBuilder resBuf = new StringBuilder();
		resBuf.append("<function");
		SpecXmlUtils.xmlEscapeAttribute(resBuf, "name", name);
		SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "size", 1);
		resBuf.append(">\n");
		resBuf.append(Varnode.buildXMLAddress(addr));
		resBuf.append("</function>\n");
		return resBuf.toString();
	}

	public static ErrorHandler getErrorHandler(final Object errOriginator,
			final String targetName) {
		return new ErrorHandler() {
			@Override
			public void error(SAXParseException exception) throws SAXException {
				Msg.error(errOriginator, "Error parsing " + targetName, exception);
			}

			@Override
			public void fatalError(SAXParseException exception) throws SAXException {
				Msg.error(errOriginator, "Fatal error parsing " + targetName, exception);
			}

			@Override
			public void warning(SAXParseException exception) throws SAXException {
				Msg.warn(errOriginator, "Warning parsing " + targetName, exception);
			}
		};
	}

	public static Namespace findOverrideSpace(Function func) {
		SymbolTable symtab = func.getProgram().getSymbolTable();
		return findNamespace(symtab, func, "override");
	}

	public static Namespace findCreateOverrideSpace(Function func) {
		SymbolTable symtab = func.getProgram().getSymbolTable();
		return findCreateNamespace(symtab, func, "override");
	}

	public static Namespace findNamespace(SymbolTable symtab, Namespace parent, String name) {
		return symtab.getNamespace(name, parent);
	}

	public static void createLabelSymbol(SymbolTable symtab, Address addr, String name,
			Namespace namespace, SourceType source, boolean useLocalNamespace)
					throws InvalidInputException {
		if (namespace == null && useLocalNamespace) {
			namespace = symtab.getNamespace(addr);
		}
		symtab.createLabel(addr, name, namespace, source);
	}

	public static void deleteSymbol(SymbolTable symtab, Address addr, String name, Namespace space)
			throws InvalidInputException {
		Symbol s = symtab.getSymbol(name, addr, space);
		if (s == null) {
			throw new InvalidInputException("Symbol " + name + " not found!");
		}
		if (s.getSource() == SourceType.DEFAULT) {
			throw new InvalidInputException(
				"Deleting the default symbol \"" + name + "\" @ " + addr + " is not allowed.");
		}

		boolean success = symtab.removeSymbolSpecial(s);
		if (!success) {
			throw new InvalidInputException(
				"Couldn't delete the symbol \"" + name + "\" @ " + addr + ".");
		}
	}

	public static boolean clearNamespace(SymbolTable symtab, Namespace space)
			throws InvalidInputException {
		SymbolIterator iter = symtab.getSymbols(space);
		ArrayList<Address> addrlist = new ArrayList<Address>();
		ArrayList<String> namelist = new ArrayList<String>();
		while (iter.hasNext()) {
			Symbol sym = iter.next();
			if (!(sym instanceof CodeSymbol)) {
				return false;
			}
			addrlist.add(sym.getAddress());
			namelist.add(sym.getName());
		}
		for (int i = 0; i < addrlist.size(); ++i) {
			deleteSymbol(symtab, addrlist.get(i), namelist.get(i), space);
		}
		return true;
	}

	public static Namespace findCreateNamespace(SymbolTable symtab, Namespace parentspace,
			String name) {
		Namespace res = findNamespace(symtab, parentspace, name);
		if (res == null) {
			try {
				return symtab.createNameSpace(parentspace, name, SourceType.USER_DEFINED);
			}
			catch (DuplicateNameException e) {
				return null;
			}
			catch (InvalidInputException e) {
				return null;
			}
		}
		return res;
	}

	/**
	 * Create XML parse tree from an input XML string
	 *
	 * TODO: this probably doesn't belong here.
	 *
	 * @param xml is the XML string to parse
	 * @param handler is the handler to use for parsing errors
	 * @return the XML tree
	 *
	 * @throws PcodeXMLException for format errors in the XML
	 */
	static public XmlPullParser stringTree(InputStream xml, ErrorHandler handler)
			throws PcodeXMLException {
		try {
			XmlPullParser parser =
					XmlPullParserFactory.create(xml, "Decompiler Result Parser", handler, false);
			return parser;
		}
		catch (Exception e) {
			throw new PcodeXMLException("XML parsing error: " + e.getMessage(), e);
		}
	}

	static public void createNamespaceTag(StringBuilder buf, Namespace namespc) {
		if (namespc == null) {
			return;
		}
		ArrayList<String> arr = new ArrayList<String>();
		Namespace curspc = namespc;
		while (curspc != null) {
			arr.add(0, curspc.getName());
			curspc = curspc.getParentNamespace();
		}
		buf.append("<val/>\n"); // Force global scope to have empty name
		for (int i = 1; i < arr.size(); ++i) {
			buf.append("<val>");
			SpecXmlUtils.xmlEscape(buf, arr.get(i));
			buf.append("</val>\n");
		}
	}

	/**
	 * @param tagname -- Name of tag to search for
	 * @param doc -- String through which to search for tags
	 * @return all characters between beginning and ending XML tags, excluding tags themselves
	 */
	static public String tagFindExclude(String tagname, String doc) {
		if (doc == null) {
			return null;
		}
		int length = tagname.length();
		int bindex = doc.indexOf("<" + tagname);
		if (bindex == -1) {
			return null;
		}
		if (bindex + length + 3 > doc.length()) {
			return null;
		}
		if (doc.charAt(bindex + length + 1) == '/') {
			return "";
		}
		int eindex = doc.indexOf("</" + tagname + ">");
		if (eindex == -1) {
			return null;
		}
		return doc.substring(bindex + length + 2, eindex);
	}
}
