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
package ghidra.app.plugin.core.compositeeditor;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.NoSuchElementException;

import docking.widgets.OptionDialog;
import docking.widgets.dialogs.InputDialog;
import docking.widgets.dialogs.InputDialogListener;
import docking.widgets.fieldpanel.support.FieldRange;
import docking.widgets.fieldpanel.support.FieldSelection;
import ghidra.docking.settings.SettingsImpl;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.InsufficientBytesException;
import ghidra.util.Msg;
import ghidra.util.exception.*;

class StructureEditorModel extends CompEditorModel {

	private static final long serialVersionUID = 1L;
	private static final int OFFSET = 0;
	private static final int LENGTH = 1;
	private static final int MNEMONIC = 2;
	private static final int DATATYPE = 3;
	private static final int FIELDNAME = 4;
	private static final int COMMENT = 5;

	StructureEditorModel(StructureEditorProvider provider, boolean showHexNumbers) {
		super(provider);
		headers = new String[] { "Offset", "Length", "Mnemonic", "DataType", "Name", "Comment" };
		columnWidths = new int[] { 75, 75, 100, 100, 100, 150 };
		columnOffsets = new int[headers.length];
		adjustOffsets();
		this.showHexNumbers = showHexNumbers;
	}

	@Override
	public int getOffsetColumn() {
		return OFFSET;
	}

	@Override
	public int getLengthColumn() {
		return LENGTH;
	}

	@Override
	public int getMnemonicColumn() {
		return MNEMONIC;
	}

	@Override
	public int getDataTypeColumn() {
		return DATATYPE;
	}

	@Override
	public int getNameColumn() {
		return FIELDNAME;
	}

	@Override
	public int getCommentColumn() {
		return COMMENT;
	}

	@Override
	public void load(Composite dataType, boolean useOffLineCategory) {
		super.load(dataType, useOffLineCategory);
	}

	@Override
	public void load(Composite dataType) {
		super.load(dataType);
	}

	/**
	 * Returns the number of component rows in the viewer. There may be a
	 * blank row at the end for selecting. Therefore this number can be
	 * different than the actual number of components currently in the
	 * structure being viewed.
	 *
	 * @return the number of rows in the model
	 */
	@Override
	public int getRowCount() {
		int componentCount = getNumComponents();
		int rowCount = componentCount + 1; // add blank edit row
		Structure viewStruct = (Structure) viewComposite;
		if (viewStruct != null && viewStruct.hasFlexibleArrayComponent()) {
			++rowCount;
		}
		return rowCount;
	}

	/**
	 * Returns an attribute value for the cell at <I>columnIndex</I>
	 * and <I>rowIndex</I>.
	 *
	 * @param	rowIndex	the row whose value is to be looked up
	 * @param	columnIndex 	the column whose value is to be looked up
	 * @return	the value Object at the specified cell
	 */
	@Override
	public Object getValueAt(int rowIndex, int columnIndex) {

		if ((viewComposite == null) || (rowIndex < 0) || (columnIndex < 0) ||
			(columnIndex >= getColumnCount())) {
			if (columnIndex == getDataTypeColumn()) {
				return null;
			}
			return "";
		}

		DataTypeComponent dtc = getComponent(rowIndex);

		if (dtc == null) {
			if (columnIndex == getDataTypeColumn()) {
				return null;
			}
			return "";
		}

		boolean isFlexArrayComponent = dtc.isFlexibleArrayComponent();
		String value = null;
		DataType dt;
		int dtLen;
		if (columnIndex == getOffsetColumn()) {
			int offset = dtc.getOffset();
			value = showHexNumbers ? getHexString(offset, true) : Integer.toString(offset);
		}
		else if (columnIndex == getLengthColumn()) {
			int length = dtc.getLength();
			value = showHexNumbers ? getHexString(length, true) : Integer.toString(length);
		}
		else if (columnIndex == getMnemonicColumn()) {
			dt = dtc.getDataType();
			value = dt.getMnemonic(new SettingsImpl());
			if (isFlexArrayComponent) {
				value += "[0]";
			}
			else {
				int compLen = dtc.getLength();
				dtLen = dtc.getDataType().getLength();
				if (dtLen > compLen) {
					value = "TooBig: " + value + " needs " + dtLen + " has " + compLen;
				}
			}
		}
		else if (columnIndex == getDataTypeColumn()) {
			dt = dtc.getDataType();
			dtLen = dt.getLength();
			return DataTypeInstance.getDataTypeInstance(dt, (dtLen > 0) ? dtLen : dtc.getLength());
		}
		else if (columnIndex == getNameColumn()) {
			value = getComponent(rowIndex).getFieldName();
		}
		else if (columnIndex == getCommentColumn()) {
			value = getComponent(rowIndex).getComment();
		}

		return (value == null) ? "" : value;
	}

	@Override
	public DataTypeComponent getComponent(int rowIndex) {
		int numComponents = getNumComponents();
		if (numComponents == 0 || rowIndex < 0 || rowIndex == numComponents) {
			return null;
		}
		Structure viewStruct = (Structure) viewComposite;
		if (rowIndex == (numComponents + 1)) {
			return viewStruct.getFlexibleArrayComponent();
		}
		if (rowIndex > numComponents) {
			return null;
		}
		if (isShowingUndefinedBytes()) {
			return viewComposite.getComponent(rowIndex);
		}
		DataTypeComponent[] definedComponents = viewStruct.getDefinedComponents();
		return definedComponents[rowIndex];
	}

	@Override
	public int getNumComponents() {
		if (viewComposite == null) {
			return 0;
		}
		if (isShowingUndefinedBytes()) {
			if (viewComposite.isNotYetDefined()) {
				return 0;
			}
			return viewComposite.getNumComponents();
		}
		DataTypeComponent[] definedComponents = ((Structure) viewComposite).getDefinedComponents();
		return definedComponents.length;
	}

	@Override
	protected boolean canConvertToFlexibleArray(int rowIndex) {
		if (!(viewComposite instanceof Structure)) {
			return false;
		}
		if (((Structure) viewComposite).hasFlexibleArrayComponent()) {
			return false;
		}
		if (rowIndex != (getNumComponents() - 1)) {
			return false;
		}
		DataTypeComponent dtc = getComponent(rowIndex);
		DataType dt = dtc.getDataType();
		if (dt instanceof TypeDef) {
			dt = ((TypeDef) dt).getBaseDataType();
		}
		if (dt instanceof Dynamic || dt instanceof FactoryDataType) {
			return false;
		}
		return true;
	}

	@Override
	protected void convertToFlexibleArray(int rowIndex) throws UsrException {
		if (!canConvertToFlexibleArray(rowIndex)) {
			// should be avoided by constraining minimum array size and data type
			throw new UsrException("Flexible array not permitted");
		}
		DataTypeComponent dtc = getComponent(rowIndex);
		Structure struct = (Structure) viewComposite;
		struct.setFlexibleArrayComponent(dtc.getDataType(), dtc.getFieldName(), dtc.getComment());
		delete(rowIndex);
		selection.addRange(rowIndex + 1, rowIndex + 2); // select flex component
		selectionChanged();
	}

	@Override
	protected boolean isSizeEditable() {
		return !isAligned();
	}

	void setStructureSize(int size) {
		if (viewComposite == null) {
			return;
		}
		int currentLength = viewComposite.isNotYetDefined() ? 0 : viewComposite.getLength();
		if (currentLength == size) {
			return;
		}
		Structure structure = (Structure) viewComposite;
		if (currentLength < size) {
			// Increasing structure length.
			structure.growStructure(size - currentLength);
		}
		else {
			DataTypeComponent dtc = structure.getComponentAt(size);
			int ordinal = dtc.getOrdinal();
			if (dtc.getOffset() != size) {
				structure.clearComponent(ordinal);
				dtc = structure.getComponentAt(size);
				ordinal = dtc.getOrdinal();
			}
			int numComponents = structure.getNumComponents();
			for (int index = numComponents - 1; index >= ordinal; index--) {
				structure.delete(index);
			}
		}
		updateAndCheckChangeState();
		fireTableDataChanged();
	}

	/**
	 *  returns whether or not a particular component row and field in this
	 *  structure is editable.
	 *  <P>Warning: There shouldn't be a selection when this is called.
	 *
	 * @param rowIndex the component index.
	 * @param columnIndex the index for the field of the component.
	 */
	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		if (getNumSelectedRows() != 1) {
			return false;
		}
		if ((rowIndex < 0) || (rowIndex >= getRowCount())) {
			return false;
		}
		// There shouldn't be a selection when this is called.
		switch (columnIndex) {
			case DATATYPE:
				return true;
			case FIELDNAME:
			case COMMENT:
				DataTypeComponent dtc = getComponent(rowIndex);
				if (dtc == null) {
					return false;
				}
				if (dtc.isFlexibleArrayComponent()) {
					return true;
				}
				DataType dt = dtc.getDataType();
				if (dt == DataType.DEFAULT) {
					return false;
				}
				return true;
			default:
				return false; // User can't edit any other fields.
		}
	}

	/**
	 *  Clear the selected components.
	 *
	 * @return true if cleared.
	 *
	 * @throws UsrException if clearing isn't allowed.
	 */
	@Override
	public void clearSelectedComponents() throws UsrException {
		if (!isClearAllowed()) {
			throw new UsrException("Clearing is not allowed.");
		}
		// If we are on the selection then clear all selected.
		if (this.getNumSelectedComponentRows() <= 0) {
			throw new UsrException("Only selections can be cleared.");
		}
		clearComponents(getSelectedComponentRows());
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.compositeeditor.EditorModel#clearComponent(int)
	 */
	@Override
	public void clearComponent(int ordinal) {
		((Structure) viewComposite).clearComponent(ordinal);
	}

	/**
	 *  Clear the components at the specified indices.
	 *
	 * @param indices array of selected component indices.
	 * @return true if cleared.
	 */
	@Override
	public void clearComponents(int[] indices) {
		if (isEditingField()) {
			endFieldEditing();
		}
		Arrays.sort(indices);

		// work from back to front so our indices aren't affected by each component's clear.
		for (int i = indices.length - 1; i >= 0; i--) {
			DataTypeComponent comp = getComponent(indices[i]);
			if (comp == null) {
				continue; // must be on blank last line.
			}
			boolean isSelected = selection.containsEntirely(BigInteger.valueOf(indices[i]));
			int numBytes = comp.getLength();
			((Structure) viewComposite).clearComponent(indices[i]);

			// Adjust the selection due to the clear.
			adjustSelection(indices[i] + 1, numBytes - 1);
			if (isSelected && numBytes > 1) {
				selection.addRange(indices[i] + 1, indices[i] + numBytes);
			}

			if (indices[i] > 0) {
				consumeByComponent(indices[i] - 1);
			}
		}
		componentEdited();
	}

	@Override
	protected void deleteComponents(int[] rows) {
		if (isShowingUndefinedBytes()) {
			super.deleteComponents(rows);
			return;
		}
		int[] ordinals = convertRowsToOrdinals(rows);
		for (int i = ordinals.length - 1; i >= 0; i--) {
			viewComposite.delete(ordinals[i]);
		}
		notifyCompositeChanged();
	}

	private int[] convertRowsToOrdinals(int[] rows) {
		int[] ordinals = new int[rows.length];
		DataTypeComponent[] definedComponents = ((Structure) viewComposite).getDefinedComponents();
		for (int i = rows.length - 1; i >= 0; i--) {
			ordinals[i] = definedComponents[rows[i]].getOrdinal();
		}
		return ordinals;
	}

	@Override
	protected int convertRowToOrdinal(int rowIndex) {
		int numRowComponents = getNumComponents();
		if (rowIndex < 0 || rowIndex > numRowComponents) {
			return -1;
		}
		if (rowIndex == numRowComponents) {
			return viewComposite.getNumComponents();
		}
		if (isShowingUndefinedBytes()) {
			return rowIndex;
		}
		DataTypeComponent[] definedComponents = ((Structure) viewComposite).getDefinedComponents();
		return definedComponents[rowIndex].getOrdinal();
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.compositeeditor.EditorModel#duplicateMultiple(int, int)
	 */
	@Override
	public void duplicateMultiple(int index, int multiple) throws UsrException {
		if (isEditingField()) {
			endFieldEditing();
		}

		DataTypeComponent originalComp = getComponent(index);
		if (originalComp == null || originalComp.isFlexibleArrayComponent()) {
			throw new IllegalArgumentException("invalid component index specified");
		}
		DataType dt = originalComp.getDataType();
		int dtLen = dt.getLength();
		checkIsAllowableDataType(dt, true);

		try {
			int startIndex = index + 1;
			if (isShowingUndefinedBytes() && (dt != DataType.DEFAULT)) {
				int endIndex = startIndex + (dtLen * multiple) - 1;
				if (startIndex < getNumComponents()) {
					deleteComponentRange(startIndex, endIndex);
				}
			}
			insertComponentMultiple(startIndex, dt, originalComp.getLength(), multiple);
		}
		catch (OutOfMemoryError memExc) {
			throw memExc; // re-throw the exception.
		}

		// Adjust the selection since we added some
		componentEdited();
		lastNumDuplicates = multiple;
	}

	/**
	 *  Moves the components between the start index (inclusive) and the end
	 *  index (inclusive) to the new index (relative to the initial component set).
	 *
	 * @param startRow row index of the starting component to move.
	 * @param endRow row index of the ending component to move.
	 * @return true if components are moved.
	 */
	private boolean shiftComponentsUp(int startRow, int endRow) {
		int numComps = getNumComponents();
		if ((startRow > endRow) || startRow <= 0 || startRow >= numComps || endRow <= 0 ||
			endRow >= numComps) {
			return false;
		}
		DataTypeComponent comp = getComponent(startRow - 1);
		deleteComponent(startRow - 1);
		try {
			insert(endRow, comp.getDataType(), comp.getLength(), comp.getFieldName(),
				comp.getComment());
		}
		catch (InvalidDataTypeException e) {
			return false;
		}
		return true;
	}

	/**
	 *  Moves the components between the start index (inclusive) and the end
	 *  index (exclusive) to the new index (relative to the initial component set).
	 *
	 * @param startIndex index of the starting component to move.
	 * @param endIndex index of the ending component to move.
	 * @return true if components are moved.
	 */
	private boolean shiftComponentsDown(int startIndex, int endIndex) {
		int numComponents = getNumComponents();
		if ((startIndex > endIndex) || startIndex < 0 || startIndex >= numComponents - 1 ||
			endIndex < 0 || endIndex >= numComponents - 1) {
			return false;
		}
		DataTypeComponent comp = getComponent(endIndex + 1);
		deleteComponent(endIndex + 1);
		try {
			insert(startIndex, comp.getDataType(), comp.getLength(), comp.getFieldName(),
				comp.getComment());
		}
		catch (InvalidDataTypeException e) {
			return false;
		}
		return true;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.compositeeditor.EditorModel#moveUp()
	 */
	@Override
	public boolean moveUp() throws NoSuchElementException {
		if (selection.getNumRanges() != 1) {
			return false;
		}
		if (isEditingField()) {
			endFieldEditing();
		}
		FieldRange range = selection.getFieldRange(0);
		int startRowIndex = range.getStart().getIndex().intValue();
		int endRowIndex = range.getEnd().getIndex().intValue() - 1;
		int numSelected = endRowIndex - startRowIndex + 1;
		boolean moved = false;
		int newIndex = startRowIndex - 1;
		moved = shiftComponentsUp(startRowIndex, endRowIndex);
		if (moved) {
			componentEdited();
			FieldSelection tmpFieldSelection = new FieldSelection();
			tmpFieldSelection.addRange(newIndex, newIndex + numSelected);
			setSelection(tmpFieldSelection);
		}
		return moved;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.compositeeditor.EditorModel#moveDown()
	 */
	@Override
	public boolean moveDown() throws NoSuchElementException {
		if (selection.getNumRanges() != 1) {
			return false;
		}
		if (isEditingField()) {
			endFieldEditing();
		}
		FieldRange range = selection.getFieldRange(0);
		int startIndex = range.getStart().getIndex().intValue();
		int endIndex = range.getEnd().getIndex().intValue() - 1;
		int numSelected = endIndex - startIndex + 1;
		boolean moved = false;
		int newIndex = startIndex + 1;
		moved = shiftComponentsDown(startIndex, endIndex);
		if (moved) {
			componentEdited();
			FieldSelection tmpFieldSelection = new FieldSelection();
			tmpFieldSelection.addRange(newIndex, newIndex + numSelected);
			setSelection(tmpFieldSelection);
		}
		return moved;
	}

	// *************************************************************
	// Begin methods for determining if a type of edit action is allowed.
	// *************************************************************

	@Override
	public boolean isBitFieldAllowed() {
		return isSingleRowSelection() && !isFlexibleArraySelection();
	}

	/**
	 * Returns whether or not the selection
	 * is allowed to be changed into an array.
	 */
	@Override
	public boolean isArrayAllowed() {
		boolean allowed = false;
		if (!this.isContiguousSelection()) {
			return false;
		}
		// Get the range this index is in, if its in one.
		FieldRange range = selection.getFieldRange(0);

		DataTypeComponent comp = getComponent(range.getStart().getIndex().intValue());
		if (comp == null) {
			return false;
		}
		if (comp.isFlexibleArrayComponent()) {
			return true;
		}

		DataType dt = comp.getDataType();
		int dtLen = dt.getLength();
		// Can only create arrays from components that aren't broken.
		// (i.e. component and data type are same size.)
		if ((dtLen < 0) || (dtLen == comp.getLength())) {
			allowed = true;
		}
		return allowed;
	}

	/**
	 * Returns whether or not clearing the component at the specified index
	 * is allowed.
	 *
	 * @param currentIndex index of the component in the structure
	 */
	@Override
	public boolean isClearAllowed() {
		return hasComponentSelection() && isShowingUndefinedBytes();
	}

	/**
	 * Returns whether or not delete of the component at the selected index
	 * is allowed.
	 *
	 * @param currentIndex index of the component in the structure
	 */
	@Override
	public boolean isDeleteAllowed() {
		if (!hasSelection()) {
			return false;
		}
		int rowIndex = selection.getFieldRange(0).getStart().getIndex().intValue();
		return getComponent(rowIndex) != null;
	}

	@Override
	public void deleteSelectedComponents() throws UsrException {
		if (!isDeleteAllowed()) {
			throw new UsrException("Deleting is not allowed.");
		}
		if (isEditingField()) {
			endFieldEditing();
		}
		int rowIndex = selection.getFieldRange(0).getStart().getIndex().intValue();
		DataTypeComponent dtc = getComponent(rowIndex);
		if (dtc.isFlexibleArrayComponent()) {
			// Remove flexible array component
			((Structure) viewComposite).clearFlexibleArrayComponent();
			componentEdited();
			selection.addRange(rowIndex - 1, rowIndex);
			fixSelection();
			selectionChanged();
			return;
		}
		super.deleteSelectedComponents();
	}

	/**
	 * Returns whether or not the component at the selected index
	 * is allowed to be duplicated.
	 *
	 * @param currentIndex index of the component in the structure
	 */
	@Override
	public boolean isDuplicateAllowed() {
		boolean dupAllowed = false;
		if (this.getNumSelectedComponentRows() != 1) {
			return false;
		}

		int rowIndex = selection.getFieldRange(0).getStart().getIndex().intValue();
		// Get the range this index is in, if its in one.
		FieldRange range = getSelectedRangeContaining(rowIndex);
		boolean notInMultiLineSelection = true;
		if ((range != null) &&
			((range.getEnd().getIndex().intValue() - range.getStart().getIndex().intValue()) > 1)) {
			notInMultiLineSelection = false;
		}

		// set actions based on number of items selected
		if (notInMultiLineSelection && (rowIndex <= getNumComponents())) {
			DataTypeComponent comp = getComponent(rowIndex);
			DataType dt = comp.getDataType();
			if (viewComposite.isInternallyAligned()) {
				dupAllowed = true;
			}
			else {
				if (dt.equals(DataType.DEFAULT)) {
					return true; // Insert an undefined and push everything down.
				}
				// Can always duplicate at the end.
				if (isAtEnd(rowIndex) || onlyUndefinedsUntilEnd(rowIndex + 1)) {
					return true;
				}
				// Otherwise can only duplicate if enough room.

				// Get the size of the data type at this index and the number of
				// undefined bytes following it.
				int dtSize = dt.getLength();
				if (dtSize <= 0) {
					dtSize = comp.getLength();
				}
				int undefSize = getNumUndefinedBytesAt(rowIndex + 1);
				if (dtSize <= undefSize) {
					dupAllowed = true;
				}
			}
		}
		return dupAllowed;
	}

	/**
	 * Returns whether the selected component can be unpackaged.
	 */
	@Override
	public boolean isUnpackageAllowed() {
		// set actions based on number of items selected
		boolean unpackageAllowed = false;
		if (this.getNumSelectedComponentRows() != 1) {
			return false;
		}

		int currentIndex = selection.getFieldRange(0).getStart().getIndex().intValue();
		// Get the range this index is in, if its in one.
		FieldRange range = getSelectedRangeContaining(currentIndex);
		boolean notInMultiLineSelection = true;
		if ((range != null) &&
			((range.getEnd().getIndex().intValue() - range.getStart().getIndex().intValue()) > 1)) {
			notInMultiLineSelection = false;
		}

		// set actions based on number of items selected
		if (notInMultiLineSelection && (currentIndex < getNumComponents())) {

			DataTypeComponent comp = getComponent(currentIndex);
			DataType dt = comp.getDataType();
			// Can only unpackage components that aren't broken.
			// (i.e. component and data type are same size.)
			if (comp.getLength() == dt.getLength()) {
				// Array or structure can be unpackaged.
				if (dt instanceof Array || (dt instanceof Structure)) {
					unpackageAllowed = true;
				}
			}
		}
		return unpackageAllowed;
	}

	/**
	 * Returns whether or not addition of the specified component is allowed
	 * at the specified index. the addition could be an insert or replace as
	 * determined by the state of the edit model.
	 *
	 * @param currentIndex index of the component in the structure.
	 * @param datatype the data type to be inserted.
	 */
	@Override
	public boolean isAddAllowed(int currentIndex, DataType datatype) {
		if (currentIndex < 0 || currentIndex > getRowCount()) {
			return false;
		}

		// Don't allow arrays to be dropped on pointers or arrays.
		if (datatype instanceof Array) {
			DataTypeComponent comp = getComponent(currentIndex);
			if (comp != null) {
				DataType compDt = comp.getDataType();
				if (compDt instanceof Array || compDt instanceof Pointer) {
					return false;
				}
			}
		}

		FieldRange currentRange = getSelectedRangeContaining(currentIndex);
		// if the index isn't in the selection or is in a range of only 
		// one row then we want to handle it the same.
		boolean isOneComponent =
			(currentRange == null) || (currentRange.getStart().getIndex().intValue() +
				1 == currentRange.getEnd().getIndex().intValue());

		if (isOneComponent) {
			// TODO
			if (!isShowingUndefinedBytes() || isAtEnd(currentIndex) ||
				onlyUndefinedsUntilEnd(currentIndex + 1)) {
				return true; // allow replace of component when aligning.
			}

			// FreeForm editing mode (showing Undefined Bytes).
			// Only drop on undefined, pointer, or another type in same cycle group.
			DataTypeComponent comp = getComponent(currentIndex);
			if (comp != null) {
				DataType compDt = comp.getDataType();
				int numCompBytes = comp.getLength();
				int numFollowing = getNumUndefinedBytesAt(currentIndex + 1);
				int numAvailable = numCompBytes + numFollowing;
				// Drop on pointer.
				if (compDt instanceof Pointer ||
					DataTypeHelper.getBaseType(compDt) instanceof Pointer) {
					// Don't create undefined byte pointers.
					if (datatype.equals(DataType.DEFAULT)) {
						return false;
					}
					return true;
				}
				else if (datatype.getLength() <= numAvailable) {
					return true;
				}
				return false;
			}
			return true;
		}
		int numComps = getNumComponents();
		int firstIndex = currentRange.getStart().getIndex().intValue();
		int lastIndex = currentRange.getEnd().getIndex().intValue() - 1;
		if ((firstIndex >= numComps) || (lastIndex >= numComps)) {
			return false;
		}
		DataTypeComponent startComp = getComponent(firstIndex);
		DataTypeComponent endComp = getComponent(lastIndex);
		int numAvailable = endComp.getOffset() + endComp.getLength() - startComp.getOffset();
		if (datatype.getLength() <= numAvailable) {
			return true;
		}
		return false;
	}

	/**
	 * Returns whether or not insertion of the specified component is allowed
	 * at the specified index.
	 *
	 * @param currentIndex index of the component in the structure.
	 * @param datatype the data type to be inserted.
	 */
	@Override
	public boolean isInsertAllowed(int currentIndex, DataType datatype) {
		if (currentIndex > getNumComponents()) {
			return false;
		}
		return true;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.datamanager.editor.CompositeEditorModel#isReplaceAllowed(int, ghidra.program.model.data.DataType)
	 */
	@Override
	public boolean isReplaceAllowed(int rowIndex, DataType dataType) {

		DataTypeComponent dtc = getComponent(rowIndex);
		if (dtc == null) {
			return false;
		}

		try {
			checkIsAllowableDataType(dataType, !dtc.isFlexibleArrayComponent());
		}
		catch (InvalidDataTypeException e) {
			return false;
		}

		if (isShowingUndefinedBytes()) {
			if (isAtEnd(rowIndex)) {
				return true;
			}
			int maxBytes = dtc.getLength() + getNumUndefinedBytesAt(rowIndex + 1);
			if (dataType.getLength() > maxBytes) {
				return false;
			}
		}
		return true;
	}

	// *************************************************************
	// End of methods for determining if a type of edit action is allowed.
	// *************************************************************

	/**
	 * Gets the maximum number of bytes available for a data type that is added at the indicated
	 * index. This can vary based on whether or not it is in a selection. 
	 * <br>In unlocked mode, the size is unrestricted when no selection or single row selection. 
	 * Multi-row selection always limits the size.
	 * <br>In locked mode, single row selection is limited to selected row plus undefined bytes 
	 * following it that can be absorbed.
	 *
	 * @param rowIndex index of the row in the editor's composite data type table.
	 * @return the max length or -1 for no limit.
	 */
	@Override
	public int getMaxAddLength(int rowIndex) {
		int maxLength = Integer.MAX_VALUE;
		if (rowIndex >= getNumComponents() - 1) {
			return maxLength;
		}
		DataTypeComponent comp = getComponent(rowIndex);
		FieldRange currentRange = getSelectedRangeContaining(rowIndex);
		// if the index isn't in the selection or is in a range of only 
		// one row then we want to handle it the same.
		boolean isOneComponent =
			(currentRange == null) || (currentRange.getStart().getIndex().intValue() +
				1 == currentRange.getEnd().getIndex().intValue());

		if (isOneComponent) {
			if (!isShowingUndefinedBytes()) {
				return maxLength;
			}

			// FreeForm editing mode (showing Undefined Bytes).
			int numAvailable = comp.getLength() + getNumUndefinedBytesAt(rowIndex + 1);
			return (maxLength == -1) ? numAvailable : Math.min(maxLength, numAvailable);
		}
		DataTypeComponent startComp = getComponent(currentRange.getStart().getIndex().intValue());
		DataTypeComponent endComp = getComponent(currentRange.getEnd().getIndex().intValue() - 1);
		int numAvailable = endComp.getOffset() + endComp.getLength() - startComp.getOffset();
		return (maxLength == -1) ? numAvailable : Math.min(maxLength, numAvailable);
	}

	/**
	 * Gets the maximum number of bytes available for a new data type that 
	 * will replace the current data type at the indicated index.
	 * If there isn't a component with the indicated index, the max length 
	 * will be determined by the lock mode.
	 *
	 * @param currentIndex index of the component in the structure.
	 * @return the maximum number of bytes that can be replaced.
	 */
	@Override
	public int getMaxReplaceLength(int currentIndex) {
		if (!isShowingUndefinedBytes()) { // Can replace at any index
			return Integer.MAX_VALUE;
		}
		// Can only replace with what fits unless at last component or empty last line.
		DataTypeComponent comp = getComponent(currentIndex);
		int numComponents = getNumComponents();
		if ((currentIndex >= (numComponents - 1)) && (currentIndex <= numComponents)) {
			return Integer.MAX_VALUE; // Last component or empty entry immediately after it.
		}
		else if (comp == null) {
			return 0; // No such component. Not at valid edit index.
		}
		else if (comp.isFlexibleArrayComponent()) {
			return Integer.MAX_VALUE;
		}
		// Otherwise, get size of component and number of Undefined bytes after it.
		FieldRange range = getSelectedRangeContaining(currentIndex);
		if (range == null ||
			range.getStart().getIndex().intValue() == range.getEnd().getIndex().intValue() - 1) {
			return comp.getLength() + getNumUndefinedBytesAt(currentIndex + 1);
		}
		return getNumBytesInRange(range);
	}

	/**
	 * Returns the number of bytes that are included in the current selection
	 * range.
	 *
	 * @param range the range of indices for the component's whose sizes should
	 * be added together.
	 */
	@Override
	protected int getNumBytesInRange(FieldRange range) {
		int numBytesInRange = 0;
		if (range != null) {
			// Determine the number of bytes.
			// Get the size of the range.
			int startIndex = range.getStart().getIndex().intValue();
			int endIndex = range.getEnd().getIndex().intValue() - 1;
			DataTypeComponent startComp = getComponent(startIndex);
			DataTypeComponent endComp = getComponent(endIndex);
			numBytesInRange = endComp.getOffset() + endComp.getLength();
			numBytesInRange -= startComp.getOffset();
		}
		return numBytesInRange;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.datamanager.editor.CompositeEditorModel#insert(int, ghidra.program.model.data.DataType, int, java.lang.String, java.lang.String)
	 */
	@Override
	protected DataTypeComponent insert(int rowIndex, DataType dataType, int length, String name,
			String comment) throws InvalidDataTypeException {
		checkIsAllowableDataType(dataType, true);
		try {
			DataTypeComponent dtc = getComponent(rowIndex);
			if (dtc != null && dtc.isFlexibleArrayComponent()) {
				Structure struct = (Structure) viewComposite;
				dtc = struct.setFlexibleArrayComponent(dataType, dtc.getFieldName(),
					dtc.getComment());
			}
			else {
				dtc = ((Structure) viewComposite).insert(rowIndex, dataType, length, name, comment);
				if (rowIndex <= row) {
					row++;
				}
			}
			adjustSelection(rowIndex, 1);
			// Consume undefined bytes that may have been added, if needed.
			consumeByComponent(rowIndex - 1);
			return dtc;
		}
		catch (IllegalArgumentException exc) {
			throw new InvalidDataTypeException(exc.getMessage());
		}
	}

	@Override
	protected void insert(int rowIndex, DataType dataType, int length, int numCopies)
			throws InvalidDataTypeException {
		checkIsAllowableDataType(dataType, true);
		int componentOrdinal = convertRowToOrdinal(rowIndex);
		try {
			for (int i = 0; i < numCopies; i++) {
				viewComposite.insert(componentOrdinal, dataType, length);
			}
			if (rowIndex <= row) {
				row += numCopies;
			}
			adjustSelection(componentOrdinal, numCopies);
			// Consume undefined bytes that may have been added, if needed.
			consumeByComponent(componentOrdinal - numCopies);
		}
		catch (IllegalArgumentException exc) {
			throw new InvalidDataTypeException(exc.getMessage());
		}
	}

	@Override
	public DataTypeComponent replace(int rowIndex, DataType dt) throws UsrException {
		DataTypeComponent dtc = getComponent(rowIndex);
		if (dtc == null || !dtc.isFlexibleArrayComponent()) {
			return super.replace(rowIndex, dt);
		}
		Structure struct = (Structure) viewComposite;
		return struct.setFlexibleArrayComponent(dt, dtc.getFieldName(), dtc.getComment());
	}

	@Override
	protected DataTypeComponent replace(int rowIndex, DataType dataType, int length, String name,
			String comment) throws InvalidDataTypeException {
		// It is assumed that the replaced component is not a flexible array
		checkIsAllowableDataType(dataType, true);
		try {
			DataTypeComponent dtc = null;
			boolean isSelected = selection.containsEntirely(BigInteger.valueOf(rowIndex));
			int diffLen = 0;
			int componentOrdinal = convertRowToOrdinal(rowIndex);

			// FreeForm editing mode (showing Undefined Bytes).
			if (isShowingUndefinedBytes() && !isAtEnd(rowIndex)) {
				int origLen = getComponent(rowIndex).getLength();
				dtc = ((Structure) viewComposite).replace(componentOrdinal, dataType, length, name,
					comment);
				diffLen = origLen - dtc.getLength();
				int nextRowIndex = rowIndex + 1;
				if (diffLen < 0) {
					selection.removeRange(nextRowIndex, nextRowIndex - diffLen);
					adjustSelection(nextRowIndex, diffLen);
				}
				else if (diffLen > 0) {
					adjustSelection(nextRowIndex, diffLen);
					if (isSelected) {
						selection.addRange(nextRowIndex, nextRowIndex + diffLen);
					}
				}
				if (rowIndex < row) {
					row += diffLen;
				}
			}
			else {
				((Structure) viewComposite).delete(componentOrdinal);
				dtc = ((Structure) viewComposite).insert(componentOrdinal, dataType, length, name,
					comment);
			}
			return dtc;
		}
		catch (IllegalArgumentException exc) {
			throw new InvalidDataTypeException(exc.getMessage());
		}
	}

	/**
	 * @see ghidra.app.plugin.contrib.data.editor.CompositeEditorModel#replaceRange(int, int, ghidra.program.model.data.DataType, int)
	 */
	@Override
	protected boolean replaceRange(int startRowIndex, int endRowIndex, DataType datatype,
			int length) throws InvalidDataTypeException, InsufficientBytesException {

		if (startRowIndex > endRowIndex) {
			// TODO throw exception.
			return false;
		}

		// Get the size of the range.
		DataTypeComponent startComp = getComponent(startRowIndex);
		DataTypeComponent endComp = getComponent(endRowIndex);
		int numBytesInRange = endComp.getOffset() + endComp.getLength();
		numBytesInRange -= startComp.getOffset();

		if (length > numBytesInRange) {
			throw new InsufficientBytesException(
				"\"" + datatype.getDisplayName() + "\" does not fit in selection.");
		}

		// Determine how many copies of new data type to add.
		int numComps = numBytesInRange / length;

		// Get the field name and comment before removing.
		String fieldName = startComp.getFieldName();
		String comment = startComp.getComment();

		FieldSelection overlap = new FieldSelection();
		overlap.addRange(startRowIndex, endRowIndex + 1);
		overlap.intersect(selection);
		boolean replacedSelected = (overlap.getNumRanges() > 0);

		// Remove the selected components.
		deleteComponentRange(startRowIndex, endRowIndex);

		int beginUndefs = startRowIndex + numComps;
		// Create the new components.
		insertMultiple(startRowIndex, datatype, length, numComps);
		int indexAfterMultiple = startRowIndex + numComps;
		if (replacedSelected) {
			selection.addRange(startRowIndex, indexAfterMultiple);
			fixSelection();
		}

		DataTypeComponent comp = getComponent(startRowIndex);
		// Set the fieldname and comment the same as before
		try {
			comp.setFieldName(fieldName);
		}
		catch (DuplicateNameException exc) {
			Msg.showError(this, null, null, null);
		}
		comp.setComment(comment);

		// Create any needed undefined data types.
		int remainingLength = numBytesInRange - (numComps * length);
		if (remainingLength > 0 && isShowingUndefinedBytes()) {
			try {
				insertComponentMultiple(beginUndefs, DataType.DEFAULT, DataType.DEFAULT.getLength(),
					remainingLength);
				if (replacedSelected) {
					selection.addRange(indexAfterMultiple, indexAfterMultiple + remainingLength);
				}
			}
			catch (InvalidDataTypeException idte) {
				Msg.showError(this, null, "Structure Editor Error", idte.getMessage());
			}
		}
		else if (remainingLength < 0) {
			return false;
		}

		return true;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.datamanager.editor.CompositeEditorModel#replaceComponents()
	 */
	@Override
	protected void replaceOriginalComponents() {
		Structure dt = (Structure) getOriginalComposite();
		if (dt != null) {
			dt.replaceWith(viewComposite);
		}
		else {
			throw new RuntimeException("ERROR: Couldn't replace structure components in " +
				getOriginalDataTypeName() + ".");
		}
	}

//	/**
//	 * @see ghidra.app.plugin.data.editor.CompositeEditorModel#dataTypeSizeChanged(ghidra.program.model.data.EditableComposite, ghidra.program.model.data.DataType)
//	 */
//	public void dataTypeSizeChanged(Composite composite, DataType dt) {
//		if (isLocked()) {
//			composite.dataTypeSizeChanged(dt);
//		}
//		else {
//			DataTypeComponent[] dtc = ((Structure)composite).getDefinedComponents();
//			for(int i=0; i < dtc.length; i++) {
//				if ((dtc[i].getDataType() == dt) && (dt.getLength() > 0)) {
//					((Structure)composite).delete(i);
//					((Structure)composite).insert(i, dt, dt.getLength(), 
//								dtc[i].getFieldName(), dtc[i].getComment());
//				}
//			}
//		}
//	}

	/**
	 * 
	 */
	@Override
	void removeDtFromComponents(Composite comp) {
		DataType newDt = viewDTM.getDataType(comp.getDataTypePath());
		if (newDt == null) {
			return;
		}
		int num = getNumComponents();
		for (int i = num - 1; i >= 0; i--) {
			DataTypeComponent dtc = getComponent(i);
			DataType dt = dtc.getDataType();
			if (dt instanceof Composite) {
				Composite dtcComp = (Composite) dt;
				if (dtcComp.isPartOf(newDt)) {
					clearComponents(new int[] { i });
					String msg =
						"Components containing " + comp.getDisplayName() + " were cleared.";
					setStatus(msg, true);
				}
			}
		}
	}

	@Override
	public void setAligned(boolean aligned) {
		boolean currentViewIsAligned = viewComposite.isInternallyAligned();
		if (currentViewIsAligned == aligned) {
			return;
		}
		viewComposite.setInternallyAligned(aligned);
		if (fixSelection()) {
			selectionChanged();
		}
		notifyCompositeChanged();
	}

	public void adjustAlignment(PluginTool tool, int minAlignment) throws InvalidInputException {
		int currentViewAlignment = viewComposite.getMinimumAlignment();
		if (currentViewAlignment == minAlignment) {
			return;
		}
		viewComposite.setMinimumAlignment(minAlignment);
		notifyCompositeChanged();
	}

//	public boolean updateAndCheckChangeState() {
//		if (originalIsChanging) {
//			return false;
//		}
//		boolean compositeChanged = super.updateAndCheckChangeState();
//		if (compositeChanged) {
//			return true;
//		}
//		Structure oldStructure = (Structure)getOriginalComposite();
//		if (oldStructure == null) {
//			hadChanges = false;
//			return hadChanges;
//		}
//		Structure viewStructure = (Structure)viewComposite;
//		hadChanges = !(viewStructure.getPackingType() == oldStructure.getPackingType()
//					&& viewStructure.getMinimumAlignment() == oldStructure.getMinimumAlignment());
//		return hadChanges;
//	}

	@Override
	public void setAlignment(int minAlignment) throws InvalidInputException {
		int currentViewAlignment = viewComposite.getMinimumAlignment();
		if (currentViewAlignment == minAlignment) {
			return;
		}
		viewComposite.setMinimumAlignment(minAlignment);
		notifyCompositeChanged();
	}

	@Override
	public boolean isShowingUndefinedBytes() {
		return !viewComposite.isInternallyAligned();
	}

	public void createInternalStructure()
			throws InvalidDataTypeException, DataTypeConflictException, UsrException {

		if (selection.getNumRanges() != 1) {
			throw new UsrException("Can only create structure on a contiguous selection.");
		}
		FieldRange fieldRange = selection.getFieldRange(0);
		int minRow = fieldRange.getStart().getIndex().intValue();
		int maxRow = fieldRange.getEnd().getIndex().intValue();
		int selectedRowCount = maxRow - minRow;
		if (selectedRowCount == 1) {
			// Popup are you sure dialog.
			int choice = OptionDialog.showYesNoDialog(provider.getComponent(),
				"Create Structure From Selected Components",
				"You only have a single component selected.\nAre you sure you want to create a structure from the selection?");
			if (choice == OptionDialog.NO_OPTION) {
				// If user chooses no, then bail out.
				return;
			}
		}
		if (isEditingField()) {
			endFieldEditing();
		}
		DataTypeManager originalDTM = getOriginalDataTypeManager();
		String baseName = "struct";
		CategoryPath originalCategoryPath = getOriginalCategoryPath();
		String uniqueName = viewDTM.getUniqueName(originalCategoryPath, baseName);
		DataType conflictingDt = originalDTM.getDataType(originalCategoryPath, uniqueName);
		while (conflictingDt != null) {
			// pull the data type into the view data type manager with the conflicting name.
			viewDTM.resolve(conflictingDt, DataTypeConflictHandler.DEFAULT_HANDLER);
			// Try to get another unique name.
			uniqueName = viewDTM.getUniqueName(originalCategoryPath, baseName);
			conflictingDt = originalDTM.getDataType(originalCategoryPath, uniqueName);
		}

		String specifiedName =
			showNameDialog(uniqueName, originalCategoryPath, viewComposite.getName(), originalDTM);
		if (specifiedName == null) {
			return;
		}
		uniqueName = specifiedName;

		int length = 0;
		final StructureDataType structureDataType =
			new StructureDataType(originalCategoryPath, uniqueName, length, originalDTM);
// Get data type components to make into structure.
		for (int rowIndex = minRow; rowIndex < maxRow; rowIndex++) {
			DataTypeComponent component = getComponent(rowIndex);
			int compLength = component.getLength();
			length += compLength;
			structureDataType.add(component.getDataType(), compLength, component.getFieldName(),
				component.getComment());
		}
		DataType addedDataType = createDataTypeInOriginalDTM(structureDataType);
		if (viewComposite.isInternallyAligned()) {
			deleteSelectedComponents();
			insert(minRow, addedDataType, addedDataType.getLength());
		}
		else {
			clearSelectedComponents();
			replace(minRow, addedDataType, addedDataType.getLength());
		}
	}

	public String showNameDialog(final String defaultName, final CategoryPath catPath,
			final String parentStructureName, final DataTypeManager applyDTM) {
		InputDialogListener listener = dialog -> {
			String name = dialog.getValue();
			if ((name == null) || (name.length() == 0)) {
				dialog.setStatusText("A name must be specified.");
				return false;
			}
			if (name.equals(parentStructureName)) {
				dialog.setStatusText("The name cannot match the external structure name.");
				return false;
			}
			DataTypeManager originalDTM = getOriginalDataTypeManager();
			DataType conflictingDt = originalDTM.getDataType(getOriginalCategoryPath(), name);
			if (conflictingDt != null) {
				dialog.setStatusText("A data type named \"" + name + "\" already exists.");
				return false;
			}
			return true;
		};

		String title = "Specify the Structure's Name";
		InputDialog nameStructureDialog =
			new InputDialog(title, new String[] { "New Structure's Name: " },
				new String[] { defaultName }, true, listener);

		provider.getPlugin().getTool().showDialog(nameStructureDialog);

		if (nameStructureDialog.isCanceled()) {
			return null;
		}
		return nameStructureDialog.getValue();

	}

	private DataType createDataTypeInOriginalDTM(StructureDataType structureDataType) {
		boolean commit = false;
		DataTypeManager originalDTM = getOriginalDataTypeManager();
		int transactionID = originalDTM.startTransaction("Creating " + structureDataType.getName());
		try {
			DataType addedDataType =
				originalDTM.addDataType(structureDataType, DataTypeConflictHandler.DEFAULT_HANDLER);
			commit = true;
			return addedDataType;
		}
		finally {
			originalDTM.endTransaction(transactionID, commit);
		}
	}
}
