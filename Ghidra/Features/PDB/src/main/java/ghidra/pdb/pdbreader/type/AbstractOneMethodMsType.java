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

public abstract class AbstractOneMethodMsType extends AbstractMsType {

	protected ClassFieldMsAttributes attribute;
	protected AbstractTypeIndex procedureTypeRecordIndex;
	protected long offsetInVFTableIfIntroVirtual;
	protected AbstractString name;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException upon error parsing a field.
	 */
	public AbstractOneMethodMsType(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		create();
		attribute = new ClassFieldMsAttributes(reader);
		procedureTypeRecordIndex.parse(reader);
		pdb.pushDependencyStack(
			new CategoryIndex(CategoryIndex.Category.DATA, procedureTypeRecordIndex.get()));
		pdb.popDependencyStack();
		if ((attribute.getPropertyVal() == 0x04) || (attribute.getPropertyVal() == 0x06)) {
			offsetInVFTableIfIntroVirtual = reader.parseUnsignedIntVal();
		}
		else {
			offsetInVFTableIfIntroVirtual = 0;
		}
		name.parse(reader);
		reader.skipPadding();
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		// No API for this.  Just outputting something that might be useful.
		// At this time, not doing anything with bind here; don't think it is warranted.
		builder.append("<");
		builder.append(attribute);
		builder.append(": ");
		builder.append(pdb.getTypeRecord(procedureTypeRecordIndex.get()));
		builder.append(",");
		builder.append(offsetInVFTableIfIntroVirtual);
		builder.append(">");
	}

	/**
	 * Creates subcomponents for this class, which can be deserialized later.
	 * <P>
	 * Implementing class must initialize {@link #procedureTypeRecordIndex} and {@link #name}.
	 */
	protected abstract void create();

}
