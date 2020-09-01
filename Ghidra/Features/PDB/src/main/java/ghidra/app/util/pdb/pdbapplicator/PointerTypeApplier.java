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
package ghidra.app.util.pdb.pdbapplicator;

import java.math.BigInteger;

import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.app.util.bin.format.pdb2.pdbreader.RecordNumber;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.*;
import ghidra.program.model.data.*;
import ghidra.util.exception.CancelledException;

/**
 * Applier for {@link AbstractPointerMsType} types.
 */
public class PointerTypeApplier extends AbstractMsTypeApplier {

	private static AbstractMsType validateType(AbstractMsType type)
			throws IllegalArgumentException {
		if (!(type instanceof AbstractPointerMsType)) {
			throw new IllegalArgumentException(
				"PDB Incorrectly applying " + type.getClass().getSimpleName() + " to " +
					PointerTypeApplier.class.getSimpleName());
		}
		return type;
	}

	private boolean isFunctionPointer = false;

	/**
	 * Constructor for pointer type applier, for transforming a enum into a
	 *  Ghidra DataType.
	 * @param applicator {@link PdbApplicator} for which this class is working.
	 * @param msType {@link AbstractPointerMsType} to process
	 * @throws IllegalArgumentException Upon invalid arguments.
	 */
	public PointerTypeApplier(PdbApplicator applicator, AbstractMsType msType)
			throws IllegalArgumentException {
		super(applicator, validateType(msType));
	}

	public boolean isFunctionPointer() {
		return isFunctionPointer;
	}

	@Override
	public BigInteger getSize() {
		return ((AbstractPointerMsType) msType).getSize();
	}

	@Override
	public void apply() throws PdbException, CancelledException {
		if (msType instanceof DummyMsType) {
			dataType = new PointerDataType(applicator.getDataTypeManager());
		}
		else {
			dataType = applyAbstractPointerMsType((AbstractPointerMsType) msType);
		}
	}

	@Override
	public void resolve() {
		// Do not resolve pointer types... will be resolved naturally, as needed
	}

	public AbstractMsTypeApplier getUnmodifiedUnderlyingTypeApplier() {
		AbstractMsTypeApplier thisUnderlyingTypeApplier =
			applicator.getTypeApplier(((AbstractPointerMsType) msType).getUnderlyingRecordNumber());

		// TODO: does not recurse below one level of modifiers... consider doing a recursion.
		if (thisUnderlyingTypeApplier instanceof ModifierTypeApplier) {
			ModifierTypeApplier x = (ModifierTypeApplier) thisUnderlyingTypeApplier;
			RecordNumber recNum =
				((AbstractModifierMsType) (x.getMsType())).getModifiedRecordNumber();
			thisUnderlyingTypeApplier = applicator.getTypeApplier(recNum);
		}
		return thisUnderlyingTypeApplier;
	}

	private DataType applyAbstractPointerMsType(AbstractPointerMsType type) {
		AbstractMsTypeApplier underlyingApplier =
			applicator.getTypeApplier(type.getUnderlyingRecordNumber());

		if (underlyingApplier instanceof ProcedureTypeApplier) {
			isFunctionPointer = true;
		}

		//DataType underlyingType = underlyingApplier.getCycleBreakType(); // out 20191211
		DataType underlyingType = underlyingApplier.getCycleBreakType();
		if (underlyingType == null) {
			// TODO: we have seen underlyingTypeApplier is for NoTypeApplier for VtShapeMsType
			//  Figure it out, and perhaps create an applier that creates a structure or something?
			return new VoidDataType(applicator.getDataTypeManager());
//			throw new PdbException("Underlying type missing for pointer.");
		}

		int size = getSizeInt();
		if (size == applicator.getDataOrganization().getPointerSize()) {
			size = -1; // Use default
		}
		Pointer pointer =
			new PointerDataType(underlyingType, size, applicator.getDataTypeManager());
		return pointer;
	}

}
