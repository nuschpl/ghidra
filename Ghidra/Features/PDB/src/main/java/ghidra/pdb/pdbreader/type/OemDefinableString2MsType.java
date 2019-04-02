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
package ghidra.pdb.pdbreader.type;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.datatype.microsoft.GUID;
import ghidra.pdb.PdbByteReader;
import ghidra.pdb.PdbException;
import ghidra.pdb.pdbreader.*;

/**
 * A class for a specific PDB data type.
 * <P>
 * For more information about PDBs, consult the Microsoft PDB API, see
 * <a href="https://devblogs.microsoft.com/cppblog/whats-inside-a-pdb-file">
 * What's inside a PDB File</a>.
 */
public class OemDefinableString2MsType extends AbstractMsType {

	public static final int PDB_ID = 0x1011;

	private GUID guid; // = new GUID(0, (short) 0, (short) 0, initGuidField4);
	private List<AbstractTypeIndex> typeIndices = new ArrayList<>();
	private byte[] remainingBytes;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public OemDefinableString2MsType(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		guid = reader.parseGUID();
		int count = reader.parseInt();
		for (int i = 0; i < count; i++) {
			AbstractTypeIndex typeIndex = new TypeIndex32();
			typeIndex.parse(reader);
			typeIndices.add(typeIndex);
		}
		//TODO: We do not know what "OEM-defined" data remains.  For now, just grabbing rest.
		remainingBytes = reader.parseBytesRemaining();
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		builder.append(String.format("OEM Definable String 2\n"));
		builder.append(String.format("  GUID: %s\n", guid.toString()));
		builder.append(String.format("  count: %d\n", typeIndices.size()));
		for (int i = 0; i < typeIndices.size(); i++) {
			builder.append(
				String.format("    typeIndex[%d]: 0x%08x\n", i, typeIndices.get(i).get()));
		}
		builder.append(String.format("  additional data length: %d\n", remainingBytes.length));
	}

}
