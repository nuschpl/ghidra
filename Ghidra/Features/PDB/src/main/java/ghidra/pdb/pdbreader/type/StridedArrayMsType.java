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

import ghidra.pdb.PdbByteReader;
import ghidra.pdb.PdbException;
import ghidra.pdb.pdbreader.*;

/**
 * A class for a specific PDB data type.
 * <P>
 * For more information about PDBs, consult the Microsoft PDB API, see
 * <a href="https://devblogs.microsoft.com/cppblog/whats-inside-a-pdb-file">
 * What's inside a PDB File</a>.
 * <P>
 * We decided to make this a derivation of {@link AbstractArrayMsType}.  Could make it its own
 *  if we decide to do that.
 * <P>
 * TODO: We are currently not outputting stride information--might need to create overloaded
 *  method called by emit.
 */
public class StridedArrayMsType extends AbstractArrayMsType {

	public static final int PDB_ID = 0x1516;

	private long stride;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException upon error parsing a field.
	 */
	public StridedArrayMsType(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	/**
	 * Returns the size of the stride for this Strided Array.
	 * @return Size of the stride.
	 */
	public long getStride() {
		return stride;
	}

	@Override
	protected void create() {
		elementTypeIndex = new TypeIndex32();
		indexTypeIndex = new TypeIndex32();
		name = new StringNt();
	}

	@Override
	protected void parseExtraFields(PdbByteReader reader) throws PdbException {
		stride = reader.parseUnsignedIntVal();
	}

}
