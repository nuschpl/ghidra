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
package ghidra.app.util.bin.format.macho.commands;

import java.io.IOException;
import java.util.ArrayList;

import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a dylib_reference structure.
 * 
 * @see <a href="https://opensource.apple.com/source/dyld/dyld-832.7.3/include/mach-o/fixup-chains.h.auto.html">mach-o/fixup-chains.h/a> 
 */
public class DyldChainedImports implements StructConverter {
	private static final int DYLD_CHAINED_IMPORT = 1;
	private static final int DYLD_CHAINED_IMPORT_ADDEND = 2;
	private static final int DYLD_CHAINED_IMPORT_ADDEND64 = 3;

	private int imports_count;
	private int imports_format;
	private long imports_offset;
	private DyldChainImport chainImports[];

	static DyldChainedImports createDyldChainedImports(FactoryBundledWithBinaryReader reader,
			DyldChainedFixupHeader cfh) throws IOException {
		DyldChainedImports dyldChainedImports =
			(DyldChainedImports) reader.getFactory().create(DyldChainedImports.class);
		dyldChainedImports.initDyldChainedStartsInImage(reader, cfh);
		return dyldChainedImports;
	}

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
	 */
	public DyldChainedImports() {
	}

	private void initDyldChainedStartsInImage(FactoryBundledWithBinaryReader reader,
			DyldChainedFixupHeader cfh) throws IOException {

		long ptrIndex = reader.getPointerIndex();
		imports_offset = ptrIndex;

		this.imports_count = cfh.getImports_count();
		this.imports_format = cfh.getImports_format();

		ArrayList<DyldChainImport> starts = new ArrayList<>();
		for (int i = 0; i < imports_count; i++) {
			starts.add(DyldChainImport.createDyldChainImport(reader, cfh, imports_format));
		}
		chainImports = starts.toArray(DyldChainImport[]::new);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		DataType chainImportDt = chainImports[0].toDataType();
		DataType dt = new ArrayDataType(chainImportDt, imports_count, chainImportDt.getLength());

		return dt;
	}

	public int getImportsCount() {
		return imports_count;
	}

	public long getImportsOffset() {
		return imports_offset;
	}

	public DyldChainImport[] getChainedImports() {
		return chainImports;
	}

	public DyldChainImport getChainImport(int ordinal) {
		if (ordinal < 0 || ordinal >= imports_count) {
			return null;
		}
		return chainImports[ordinal];
	}

	public void initSymbols(FactoryBundledWithBinaryReader reader,
			DyldChainedFixupHeader dyldChainedFixupHeader) throws IOException {
		long ptrIndex = reader.getPointerIndex();

		for (DyldChainImport dyldChainImport : chainImports) {
			reader.setPointerIndex(ptrIndex + dyldChainImport.getNameOffset());
			dyldChainImport.initString(reader);
		}
	}
}
