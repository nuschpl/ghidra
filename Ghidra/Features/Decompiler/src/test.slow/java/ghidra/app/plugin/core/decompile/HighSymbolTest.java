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
package ghidra.app.plugin.core.decompile;

import static org.junit.Assert.*;

import java.util.List;

import org.junit.Test;

import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangVariableToken;
import ghidra.app.decompiler.component.ClangTextField;
import ghidra.app.decompiler.component.DecompilerPanel;
import ghidra.app.plugin.core.decompile.actions.RenameGlobalVariableTask;
import ghidra.app.plugin.core.decompile.actions.RenameVariableTask;
import ghidra.program.database.symbol.CodeSymbol;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

public class HighSymbolTest extends AbstractDecompilerTest {
	@Override
	protected String getProgramName() {
		return "Winmine__XP.exe.gzf";
	}

	protected ClangTextField getLineStarting(String val) {
		DecompilerPanel panel = provider.getDecompilerPanel();
		List<Field> fields = panel.getFields();
		for (Field field : fields) {
			ClangTextField textField = (ClangTextField) field;
			String text = textField.getText().trim();
			if (text.startsWith(val)) {
				return textField;
			}
		}
		return null;
	}

	protected ClangTextField getLineContaining(String val) {
		DecompilerPanel panel = provider.getDecompilerPanel();
		List<Field> fields = panel.getFields();
		for (Field field : fields) {
			ClangTextField textField = (ClangTextField) field;
			String text = textField.getText();
			if (text.contains(val)) {
				return textField;
			}
		}
		return null;
	}

	protected HighFunction getHighFunction() {
		return provider.getController().getHighFunction();
	}

	private void renameGlobalVariable(HighSymbol highSymbol, Varnode exact, String newName) {
		Address addr = highSymbol.getStorage().getMinAddress();
		RenameGlobalVariableTask rename = new RenameGlobalVariableTask(provider.getTool(),
			highSymbol.getName(), addr, highSymbol.getProgram());

		assertTrue(rename.isValid(newName));
		modifyProgram(p -> {
			rename.commit();
		});
		waitForDecompiler();
	}

	private void renameVariable(HighSymbol highSymbol, Varnode exact, String newName) {
		RenameVariableTask rename = new RenameVariableTask(provider.getTool(), highSymbol, exact,
			SourceType.USER_DEFINED);
		assertTrue(rename.isValid(newName));
		modifyProgram(p -> {
			rename.commit();
		});
		waitForDecompiler();
	}

	private void renameExisting(HighSymbol highSymbol, Varnode exact, String newName) {
		SymbolEntry oldEntry = highSymbol.getFirstWholeMap();
		long oldId = highSymbol.getId();
		if (highSymbol.isGlobal()) {
			renameGlobalVariable(highSymbol, exact, newName);
		}
		else {
			renameVariable(highSymbol, exact, newName);
		}
		Symbol symbol = program.getSymbolTable().getSymbol(oldId);
		assertEquals(symbol.getName(), newName);
		HighFunction highFunction = getHighFunction();
		HighSymbol newHighSymbol = highFunction.getLocalSymbolMap().getSymbol(oldId);
		if (newHighSymbol == null) {
			newHighSymbol = highFunction.getGlobalSymbolMap().getSymbol(oldId);
		}
		assertNotNull(newHighSymbol);
		SymbolEntry newEntry = newHighSymbol.getFirstWholeMap();
		assertEquals(oldEntry.getStorage(), newEntry.getStorage());
	}

	@Test
	public void testHighSymbol_globalRename() {

		decompile("1001b49");

		ClangTextField line = getLineStarting("DAT_010056a0");
		FieldLocation loc = loc(line.getLineNumber(), 5);
		ClangToken token = line.getToken(loc);
		assertTrue(token instanceof ClangVariableToken);
		HighVariable variable = token.getHighVariable();
		assertTrue(variable instanceof HighGlobal);
		HighSymbol highSymbol = variable.getSymbol();
		assertTrue(highSymbol instanceof HighCodeSymbol);
		HighCodeSymbol highCode = (HighCodeSymbol) highSymbol;
		CodeSymbol codeSymbol = highCode.getCodeSymbol();
		assertNull(codeSymbol);	// A DAT_ should not have a permanent CodeSymbol
		Data data = highCode.getData();
		assertNotNull(data);
		assertEquals(data.getAddress().getOffset(), 0x10056a0L);
		assertEquals(data.getBaseDataType().getLength(), 2);

		renameGlobalVariable(highSymbol, null, "newGlobal");
		waitForDecompiler();
		line = getLineStarting("newGlobal");
		loc = loc(line.getLineNumber(), 5);
		token = line.getToken(loc);
		assertTrue(token instanceof ClangVariableToken);
		variable = token.getHighVariable();
		assertTrue(variable instanceof HighGlobal);
		highSymbol = variable.getSymbol();
		assertTrue(highSymbol instanceof HighCodeSymbol);
		highCode = (HighCodeSymbol) highSymbol;
		assertTrue(highCode.isGlobal());
		assertTrue(highCode.isNameLocked());
		assertTrue(highCode.isTypeLocked());
		codeSymbol = highCode.getCodeSymbol();
		assertNotNull(codeSymbol);
		assertEquals(codeSymbol.getID(), highCode.getId());
		renameExisting(highSymbol, null, "nameAgain");
	}

	@Test
	public void testHighSymbol_localStackDynamic() {
		decompile("10015a6");
		ClangTextField line = getLineContaining(" = 0xc;");
		FieldLocation loc = loc(line.getLineNumber(), 5);
		ClangToken token = line.getToken(loc);
		assertTrue(token instanceof ClangVariableToken);
		HighVariable variable = token.getHighVariable();
		assertTrue(variable instanceof HighLocal);
		HighSymbol highSymbol = variable.getSymbol();
		SymbolEntry entry = highSymbol.getFirstWholeMap();
		assertTrue(entry instanceof MappedEntry);		// Comes back initially as untied stack location
		int stackCount = 0;
		int regCount = 0;
		int numInst = variable.getInstances().length;
		for (Varnode var : variable.getInstances()) {
			if (var.isRegister() || var.isAddrTied()) {
				regCount += 1;
			}
			else if (var.getAddress().isStackAddress()) {
				stackCount += 1;
			}
		}
		assertTrue(stackCount > 0);		// Verify speculative merge
		assertTrue(regCount > 0);
		renameVariable(highSymbol, token.getVarnode(), "newLocal");
		line = getLineStarting("newLocal");
		loc = loc(line.getLineNumber(), 5);
		token = line.getToken(loc);
		assertTrue(token instanceof ClangVariableToken);
		variable = token.getHighVariable();
		assertTrue(variable instanceof HighLocal);
		highSymbol = variable.getSymbol();
		entry = highSymbol.getFirstWholeMap();
		assertTrue(entry instanceof DynamicEntry);	// After rename comes back as HASH
		assertTrue(entry.getPCAdress().getOffset() == 0x10016a3);
		assertTrue(highSymbol.isNameLocked());
		assertFalse(highSymbol.isTypeLocked());
		assertEquals(numInst, variable.getInstances().length);
		assertEquals(variable.getRepresentative().getAddress().getOffset(), 0xfffffffffffffff0L);
		renameExisting(highSymbol, null, "nameAgain");
	}

	@Test
	public void testHighSymbol_localArray() {
		decompile("10016ba");
		ClangTextField line = getLineStarting("wsprintfW");
		FieldLocation loc = loc(line.getLineNumber(), 14);
		ClangToken token = line.getToken(loc);
		assertTrue(token instanceof ClangVariableToken);
		assertNull(token.getHighVariable());		// No HighVariable associated with the token
		PcodeOp op = ((ClangVariableToken) token).getPcodeOp();
		Address addr = HighFunctionDBUtil.getSpacebaseReferenceAddress(provider.getProgram(), op);
		HighFunction highFunction = getHighFunction();
		LocalSymbolMap lsym = highFunction.getLocalSymbolMap();
		HighSymbol highSymbol = lsym.findLocal(addr, null);
		assertEquals(highSymbol.getName(), "local_44");
		renameVariable(highSymbol, token.getVarnode(), "newArray");
		line = getLineStarting("wsprintfW");
		token = line.getToken(loc);
		assertTrue(token instanceof ClangVariableToken);
		assertEquals(token.getText(), "newArray");		// Name has changed
		highFunction = getHighFunction();
		lsym = highFunction.getLocalSymbolMap();
		highSymbol = lsym.findLocal(addr, null);
		assertEquals(highSymbol.getName(), "newArray");
		assertTrue(highSymbol.isNameLocked());
		assertFalse(highSymbol.isTypeLocked());
		SymbolEntry entry = highSymbol.getFirstWholeMap();
		assertTrue(entry instanceof MappedEntry);
		assertEquals(entry.getStorage().getMinAddress(), addr);
		assertEquals(entry.getSize(), 64);
		renameExisting(highSymbol, null, "nameAgain");
	}

	@Test
	public void testHighSymbol_localRegister() {
		decompile("1002607");
		ClangTextField line = getLineStarting("iVar");
		FieldLocation loc = loc(line.getLineNumber(), 1);
		ClangToken token = line.getToken(loc);
		assertTrue(token instanceof ClangVariableToken);
		HighVariable variable = token.getHighVariable();
		assertTrue(variable instanceof HighLocal);
		HighSymbol highSymbol = variable.getSymbol();
		SymbolEntry entry = highSymbol.getFirstWholeMap();
		Address addr = entry.getStorage().getMinAddress();
		assertTrue(entry instanceof MappedEntry);		// Comes back initially as untied stack location
		assertEquals(addr.getAddressSpace().getName(), "register");
		renameVariable(highSymbol, token.getVarnode(), "newReg");
		line = getLineContaining("newReg < 0x40");
		assertNotNull(line);
		HighFunction highFunction = getHighFunction();
		highSymbol = highFunction.getLocalSymbolMap().findLocal(addr, entry.getPCAdress());
		assertNotNull(highSymbol);
		assertEquals(highSymbol.getName(), "newReg");
		assertTrue(highSymbol.isNameLocked());
		assertFalse(highSymbol.isTypeLocked());
		renameExisting(highSymbol, null, "nameAgain");
	}

	@Test
	public void testHighSymbol_parameter() {
		decompile("1002d7a");
		ClangTextField line = getLineContaining("strlen");
		FieldLocation loc = loc(line.getLineNumber(), 20);
		ClangToken token = line.getToken(loc);
		assertTrue(token instanceof ClangVariableToken);
		HighVariable variable = token.getHighVariable();
		assertTrue(variable instanceof HighParam);
		HighSymbol highSymbol = variable.getSymbol();
		assertEquals(highSymbol.getName(), "param_2");
		assertTrue(highSymbol.isParameter());
		assertEquals(highSymbol.getCategoryIndex(), 1);
		SymbolEntry entry = highSymbol.getFirstWholeMap();
		Address addr = entry.getStorage().getMinAddress();
		assertEquals(addr.getOffset(), 8L);
		renameExisting(highSymbol, null, "paramAgain");
	}

	@Test
	public void testHighSymbol_multipleUsePoints() {
		decompile("1001915");
		ClangTextField line = getLineContaining("0x4e");
		FieldLocation loc = loc(line.getLineNumber(), 4);
		ClangToken token = line.getToken(loc);
		assertTrue(token instanceof ClangVariableToken);
		HighVariable variable = token.getHighVariable();
		assertTrue(variable instanceof HighLocal);
		HighSymbol highSymbol = variable.getSymbol();
		SymbolEntry entry = highSymbol.getFirstWholeMap();
		assertTrue(entry instanceof MappedEntry);
		Address usepoint = token.getVarnode().getPCAddress();
		renameVariable(highSymbol, token.getVarnode(), "newLocal");
		line = getLineContaining("0x4e");
		token = line.getToken(loc);
		assertTrue(token instanceof ClangVariableToken);
		assertEquals(token.getText(), "newLocal");		// Name has changed
		variable = token.getHighVariable();
		highSymbol = variable.getSymbol();
		entry = highSymbol.getFirstWholeMap();
		assertEquals(usepoint, entry.getPCAdress());		// Make sure the same usepoint comes back
	}
}
