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

import ghidra.pdb.*;
import ghidra.pdb.pdbreader.*;

/**
 * An abstract class for Method Record attributes used for various specific PDB data type.
 */
public abstract class AbstractMethodRecordMs extends AbstractParsableItem {

	protected AbstractPdb pdb;
	protected ClassFieldMsAttributes attributes;
	protected AbstractTypeIndex procedureRecordNumber;
	protected long optionalOffset;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public AbstractMethodRecordMs(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		this.pdb = pdb;
		create();
		parseFields(reader);
		pdb.pushDependencyStack(
			new CategoryIndex(CategoryIndex.Category.DATA, procedureRecordNumber.get()));
		pdb.popDependencyStack();
	}

	@Override
	public void emit(StringBuilder builder) {
		// Making this up; no API for output.
		builder.append("<");
		builder.append(attributes);
		builder.append(": ");
		builder.append(pdb.getTypeRecord(procedureRecordNumber.get()));
		if (attributes.getPropertyVal() == 4) {
			builder.append(",");
			builder.append(optionalOffset);
		}
		builder.append(">");
	}

	/**
	 * Creates subcomponents for this class, which can be deserialized later.
	 * <P>
	 * Implementing class must initialize {@link #procedureRecordNumber}.
	 */
	protected abstract void create();

	/**
	 * Parses the fields for this type.
	 * <P>
	 * Implementing class must, in the appropriate order pertinent to itself, allocate/parse
	 * {@link #attributes}; also parse {@link #procedureRecordNumber} and {@link #optionalOffset}.
	 * @param reader {@link PdbByteReader} from which the fields are parsed.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	protected abstract void parseFields(PdbByteReader reader) throws PdbException;

}
