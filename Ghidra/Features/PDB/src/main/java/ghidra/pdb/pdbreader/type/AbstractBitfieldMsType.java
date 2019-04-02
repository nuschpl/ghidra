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
 * An abstract class for a number of specific PDB data types that share certain information.
 * <P>
 * For more information about PDBs, consult the Microsoft PDB API, see
 * <a href="https://devblogs.microsoft.com/cppblog/whats-inside-a-pdb-file">
 * What's inside a PDB File</a>.
 */
public abstract class AbstractBitfieldMsType extends AbstractMsType {

	protected AbstractTypeIndex elementTypeIndex;
	protected int length;
	protected int position;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public AbstractBitfieldMsType(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		create();
		parseFields(reader);
		pdb.pushDependencyStack(
			new CategoryIndex(CategoryIndex.Category.DATA, elementTypeIndex.get()));
		pdb.popDependencyStack();
	}

	/**
	 * Returns the type index of the element type.
	 * @return The element type.
	 */
	public int getElementTypeIndex() {
		return elementTypeIndex.get();
	}

	/**
	 * Returns the bit length of the bit-field.
	 * @return The bit length.
	 */
	public int getBitLength() {
		return length;
	}

	/**
	 * Returns the bit position of the bit-field.
	 * @return The bit position.
	 */
	public int getBitPosition() {
		return position;
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		// No documented API for output.
		pdb.getTypeRecord(elementTypeIndex.get()).emit(builder, Bind.NONE);
		builder.append(" : ");
		builder.append(length);
		builder.append(" <@");
		builder.append(position);
		builder.append(">");
	}

	/**
	 * Creates subcomponents for this class, which can be deserialized later.
	 */
	protected abstract void create();

	/**
	 * Parses the fields for this type.
	 * @param reader {@link PdbByteReader} from which the fields are parsed.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	protected abstract void parseFields(PdbByteReader reader) throws PdbException;

}
