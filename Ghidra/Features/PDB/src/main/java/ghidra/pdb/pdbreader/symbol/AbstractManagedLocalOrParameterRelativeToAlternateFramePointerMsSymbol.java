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
package ghidra.pdb.pdbreader.symbol;

import ghidra.pdb.PdbByteReader;
import ghidra.pdb.PdbException;
import ghidra.pdb.pdbreader.*;

/**
 * This class represents various flavors of Managed Local- Or Parameter-Relative-to-Virtual
 *  Frame Pointer symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractManagedLocalOrParameterRelativeToAlternateFramePointerMsSymbol
		extends AbstractMsSymbol {

	private long offset;
	private int typeIndex;
	private int register;
	private RegisterName registerName;
	private LocalVariableAttributes attributes;
	protected AbstractString name;

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException upon error parsing a field.
	 */
	public AbstractManagedLocalOrParameterRelativeToAlternateFramePointerMsSymbol(AbstractPdb pdb,
			PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		create();
		offset = reader.parseUnsignedIntVal();
		typeIndex = reader.parseInt();
		register = reader.parseUnsignedShortVal();
		registerName = new RegisterName(pdb, register);
		attributes = new LocalVariableAttributes(reader);
		name.parse(reader);
	}

	@Override
	public void emit(StringBuilder builder) {
		StringBuilder myBuilder = new StringBuilder();
		myBuilder.append(typeIndex);
		attributes.emit(myBuilder);
		builder.append(String.format("%s: %s+%08X, %s, %s", getSymbolTypeName(),
			registerName.toString(), offset, myBuilder.toString(), name.get()));
	}

	/**
	 * Creates subcomponents for this class, which can be deserialized later.
	 * <P>
	 * Implementing class must initialize {@link #name}.
	 */
	protected abstract void create();

}
