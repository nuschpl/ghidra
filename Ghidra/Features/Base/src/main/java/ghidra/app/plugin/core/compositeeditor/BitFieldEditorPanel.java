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

import java.awt.Dimension;
import java.awt.Point;
import java.awt.event.*;

import javax.swing.*;
import javax.swing.event.CellEditorListener;
import javax.swing.event.ChangeEvent;

import docking.ActionContext;
import docking.widgets.DropDownSelectionTextField;
import docking.widgets.OptionDialog;
import ghidra.app.plugin.core.compositeeditor.BitFieldPlacementComponent.BitAttributes;
import ghidra.app.plugin.core.compositeeditor.BitFieldPlacementComponent.BitFieldAllocation;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.datatype.DataTypeSelectionEditor;
import ghidra.app.util.datatype.NavigationDirection;
import ghidra.program.model.data.*;
import ghidra.util.Msg;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;
import ghidra.util.layout.*;
import resources.ResourceManager;

/**
 * <code>BitFieldEditorPanel</code> provides the ability to place bitfields
 * within unaligned structures and unions.
 */
public class BitFieldEditorPanel extends JPanel {

	private static final Icon DECREMENT_ICON = ResourceManager.loadImage("images/Minus.png");
	private static final Icon INCREMENT_ICON = ResourceManager.loadImage("images/Plus.png");

	private static final String ENTRY_ERROR_DIALOG_TITLE = "Bitfield Entry Error";

	private DataTypeManagerService dtmService;
	private Composite composite;

	private JLabel allocationOffsetLabel;
	JButton decrementButton;
	JButton incrementButton;

	private BitFieldPlacementComponent placementComponent;
	private DataType baseDataType;

	private DataTypeSelectionEditor dtChoiceEditor;
	private JTextField fieldNameTextField;
	private SpinnerNumberModel allocSizeModel;
	private JSpinnerWithMouseWheel allocSizeInput;
	private SpinnerNumberModel bitOffsetModel;
	private JSpinnerWithMouseWheel bitOffsetInput;
	private SpinnerNumberModel bitSizeModel;
	private JSpinnerWithMouseWheel bitSizeInput;

	private boolean updating = false;

	BitFieldEditorPanel(Composite composite, DataTypeManagerService dtmService) {
		super();
		this.composite = composite;

		if (composite.isInternallyAligned()) {
			// A different bitfield editor should be used for aligned composites
			throw new IllegalArgumentException("composite must be unaligned");
		}

		setLayout(new VerticalLayout(5));
		setFocusTraversalKeysEnabled(true);

		this.dtmService = dtmService;

		setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

		createPlacementPanel();

		if (composite instanceof Structure) {
			add(createAllocationOffsetPanel());
		}
		add(placementComponent);
		add(createEntryPanel());

		enableControls(false);
	}

	private JPanel createAllocationOffsetPanel() {

		JPanel panel = new JPanel(new HorizontalLayout(5));

		decrementButton = new JButton(DECREMENT_ICON);
		decrementButton.setFocusable(false);
		decrementButton.setToolTipText("Decrement allocation unit offset");
		decrementButton.addActionListener(e -> adjustAllocationOffset(-1));
		panel.add(decrementButton);

		incrementButton = new JButton(INCREMENT_ICON);
		incrementButton.setFocusable(false);
		incrementButton.setToolTipText("Increment allocation unit offset");
		incrementButton.addActionListener(e -> adjustAllocationOffset(1));
		panel.add(incrementButton);

		allocationOffsetLabel = new JLabel();
		allocationOffsetLabel.setHorizontalTextPosition(SwingConstants.LEFT);
		panel.add(allocationOffsetLabel);

		return panel;
	}

	private void adjustAllocationOffset(int delta) {
		int adjustedOffset = placementComponent.getAllocationOffset() + delta;
		if (adjustedOffset < 0 || adjustedOffset > composite.getLength()) {
			return;
		}
		placementComponent.setAllocationOffset(adjustedOffset);
		updateAllocationOffsetLabel();
	}

	private void updateAllocationOffsetLabel() {
		if (composite instanceof Structure) {
			String text =
				"Structure Offset of Allocation Unit: " + placementComponent.getAllocationOffset();
			allocationOffsetLabel.setText(text);

			int offset = placementComponent.getAllocationOffset();
			decrementButton.setEnabled(offset > 0);
			int length = composite.isNotYetDefined() ? 0 : composite.getLength();
			incrementButton.setEnabled(offset < length);
		}
	}

	private JPanel createEntryPanel() {

		JComponent baseDataTypeEditor = createDataTypeChoiceEditor();

		fieldNameTextField = new JTextField(20);
		fieldNameTextField.setFocusable(true);

		allocSizeModel = new SpinnerNumberModel(Long.valueOf(4), Long.valueOf(1), Long.valueOf(16),
			Long.valueOf(1));
		allocSizeInput = new JSpinnerWithMouseWheel(allocSizeModel);

		bitOffsetModel = new SpinnerNumberModel(Long.valueOf(0), Long.valueOf(0), Long.valueOf(31),
			Long.valueOf(1));
		bitOffsetInput = new JSpinnerWithMouseWheel(bitOffsetModel);

		bitSizeModel = new SpinnerNumberModel(Long.valueOf(4), Long.valueOf(0), Long.valueOf(4 * 8),
			Long.valueOf(1));
		bitSizeInput = new JSpinnerWithMouseWheel(bitSizeModel);

		allocSizeModel.addChangeListener(e -> update());
		bitSizeModel.addChangeListener(e -> update());
		bitOffsetModel.addChangeListener(e -> update());

		JPanel entryPanel = new JPanel(new TwoColumnPairLayout(5, 15, 5, 0));
		entryPanel.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createEtchedBorder(),
			BorderFactory.createEmptyBorder(5, 5, 5, 5)));
		entryPanel.setFocusCycleRoot(true);

		entryPanel.add(new JLabel("Base Datatype:"));
		entryPanel.add(baseDataTypeEditor);

		entryPanel.add(new JLabel("Allocation Bytes:"));
		entryPanel.add(allocSizeInput);

		entryPanel.add(new JLabel("Field Name:"));
		entryPanel.add(fieldNameTextField);

		entryPanel.add(new JLabel("Bit Size:"));
		entryPanel.add(bitSizeInput);

		entryPanel.add(new JPanel());
		entryPanel.add(new JPanel());

		entryPanel.add(new JLabel("Bit Offset:"));
		entryPanel.add(bitOffsetInput);
		return entryPanel;
	}

	private JComponent createDataTypeChoiceEditor() {

		dtChoiceEditor = new DataTypeSelectionEditor(dtmService, -1, AllowedDataTypes.BITFIELD_USE);
		dtChoiceEditor.setConsumeEnterKeyPress(false);
		dtChoiceEditor.setTabCommitsEdit(true);
		//dtChoiceEditor.setPreferredDataTypeManager(composite.getDataTypeManager());

		final DropDownSelectionTextField<DataType> dtChoiceTextField =
			dtChoiceEditor.getDropDownTextField();
		dtChoiceTextField.setBorder(UIManager.getBorder("TextField.border"));

		dtChoiceEditor.addCellEditorListener(new CellEditorListener() {
			@Override
			public void editingCanceled(ChangeEvent e) {
				dtChoiceEditor.setCellEditorValue(baseDataType); // restore
			}

			@Override
			public void editingStopped(ChangeEvent e) {
				if (!checkValidBaseDataType()) {
					dtChoiceTextField.selectAll();
				}
				else {
					baseDataType = dtChoiceEditor.getCellEditorValueAsDataType();
					if (baseDataType != null) {
						baseDataType = baseDataType.clone(composite.getDataTypeManager());
					}
					updateBitSizeModel();
					NavigationDirection direction = dtChoiceEditor.getNavigationDirection();
					if (direction == NavigationDirection.FORWARD) {
						allocSizeInput.requestFocus();
					}
					else if (direction == NavigationDirection.BACKWARD) {
						bitOffsetInput.requestFocus();
					}
				}
			}
		});

		dtChoiceEditor.getBrowseButton().setFocusable(false);

		JComponent editorComponent = dtChoiceEditor.getEditorComponent();
		Dimension preferredSize = editorComponent.getPreferredSize();
		editorComponent.setPreferredSize(new Dimension(200, preferredSize.height));
		return editorComponent;
	}

	private JPanel createPlacementPanel() {
		JPanel midPanel = new JPanel(new PairLayout(5, 5));

		JPanel leftMidPanel = new JPanel(new VerticalLayout(13));
		leftMidPanel.setBorder(BorderFactory.createEmptyBorder(12, 8, 12, 0));
		JLabel byteOffsetLabel = new JLabel("Byte Offset:", SwingConstants.RIGHT);
		byteOffsetLabel.setToolTipText("Byte Offset is relative to start of allocation unit");
		leftMidPanel.add(byteOffsetLabel);
		leftMidPanel.add(new JLabel("Bits:", SwingConstants.RIGHT));
		midPanel.add(leftMidPanel);

		placementComponent = new BitFieldPlacementComponent(composite);
		placementComponent.setFont(UIManager.getFont("TextField.font"));
		placementComponent.addMouseWheelListener(e -> bitSizeInput.mouseWheelMoved(e));

		placementComponent.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() == 1 && e.getButton() == MouseEvent.BUTTON1 &&
					bitOffsetInput.isEnabled()) {
					setBitFieldOffset(e.getPoint());
				}
//				if (e.getClickCount() == 2 && endCurrentEdit() &&
//					editBitFieldComponent(e.getPoint())) {
//					enableControls(true);
//				}
			}
//			public void mousePressed(MouseEvent e) {
//				if (e.isPopupTrigger()) {
//					setBitFieldPopupContext(e.getPoint());
//				}
//			};
		});

		JScrollPane scrollPane =
			new JScrollPane(placementComponent, ScrollPaneConstants.VERTICAL_SCROLLBAR_NEVER,
				ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
		scrollPane.getViewport().setBackground(getBackground());

		midPanel.add(scrollPane);
		return midPanel;
	}

	private boolean checkValidBaseDataType() {
		DropDownSelectionTextField<DataType> textField = dtChoiceEditor.getDropDownTextField();
		String dtName = textField.getText().trim();
		try {
			if (dtName.length() == 0 || !dtChoiceEditor.validateUserSelection()) {
				Msg.showError(BitFieldEditorPanel.class, textField, ENTRY_ERROR_DIALOG_TITLE,
					"Valid bitfield base datatype entry required");
				return false;
			}
		}
		catch (InvalidDataTypeException e) {
			Msg.showError(BitFieldEditorPanel.class, textField, ENTRY_ERROR_DIALOG_TITLE,
				"Invalid bitfield base datatype: " + e.getMessage());
			return false;
		}

		return true;
	}

	void initAdd(DataType initialBaseDataType, int allocationOffset, int bitOffset,
			boolean useCurrentAllocation) {
		if (initialBaseDataType == null) {
			initialBaseDataType = baseDataType;
		}
		if (!BitFieldDataType.isValidBaseDataType(initialBaseDataType)) {
			initialBaseDataType = IntegerDataType.dataType.clone(composite.getDataTypeManager());
		}
		placementComponent.setAllocationOffset(allocationOffset);
		long allocationSize = useCurrentAllocation ? (Long) allocSizeModel.getValue()
				: initialBaseDataType.getLength();
		placementComponent.initAdd((int) allocationSize, 1, bitOffset);
		initControls(null, initialBaseDataType);
		enableControls(true);
	}

	/**
	 * Initialize for edit of existing component or no component if bitfieldDtc is null.
	 * If null an allocation size of 4-bytes will be used but may be adjusted.
	 * @param bitfieldDtc bitfield component or null
	 * @param allocationOffset allocation offset to be used
	 * @param useCurrentAllocation retain current allocation size, otherwise
	 * use size of base datatype.
	 */
	void initEdit(DataTypeComponent bitfieldDtc, int allocationOffset,
			boolean useCurrentAllocation) {
		String initialFieldName = null;
		DataType initialBaseDataType = null;
		int allocationSize = -1;
		BitFieldAllocation bitFieldAllocation = placementComponent.getBitFieldAllocation();
		if (bitFieldAllocation != null) {
			allocationSize = bitFieldAllocation.getAllocationByteSize();
		}
		if (bitfieldDtc != null) {
			if (!bitfieldDtc.isBitFieldComponent()) {
				throw new IllegalArgumentException("unsupport data type component");
			}
			initialFieldName = bitfieldDtc.getFieldName();
			BitFieldDataType bitfieldDt = (BitFieldDataType) bitfieldDtc.getDataType();
			initialBaseDataType = bitfieldDt.getBaseDataType();
			if (!useCurrentAllocation || allocationSize < 1) {
				allocationSize = initialBaseDataType.getLength();
			}
		}
		if (allocationSize < 1) {
			allocationSize = 4;
		}
		// TODO: adjust offset and allocationSize if needed
		placementComponent.setAllocationOffset(allocationOffset);
		placementComponent.init(allocationSize, bitfieldDtc);
		initControls(initialFieldName, initialBaseDataType);
		enableControls(bitfieldDtc != null);
	}

	void componentDeleted(int ordinal) {
		placementComponent.componentDeleted(ordinal);
	}

	private void initControls(String initialFieldName, DataType initialBaseDataType) {
		updating = true;
		try {
			baseDataType = initialBaseDataType;
			dtChoiceEditor.setCellEditorValue(initialBaseDataType);
			fieldNameTextField.setText(initialFieldName);

			// Use current placementComponent to obtain initial values
			BitFieldAllocation bitFieldAllocation = placementComponent.getBitFieldAllocation();
			allocSizeModel.setValue((long) bitFieldAllocation.getAllocationByteSize());
			int allocBits = 8 * bitFieldAllocation.getAllocationByteSize();
			bitSizeModel.setValue(1L);
			bitOffsetModel.setMaximum((long) allocBits - 1);
			bitOffsetModel.setValue((long) bitFieldAllocation.getBitOffset());
			updateBitSizeModel();

			updateAllocationOffsetLabel();
		}
		finally {
			updating = false;
		}
	}

	/**
	 * @return true if actively editing or adding a bitfield
	 */
	boolean isEditing() {
		return placementComponent.isEditing();
	}

	/**
	 * @return true if actively adding a bitfield
	 */
	boolean isAdding() {
		return placementComponent.isAdding();
	}

	boolean endCurrentEdit() {
		if (placementComponent.isEditing()) {
			String currentOp = placementComponent.isAdding() ? "add" : "edit";
			int option = OptionDialog.showYesNoDialog(this, "Confirm Edit Action",
				"Cancel current bitfield " + currentOp + " operation?");
			if (option != OptionDialog.YES_OPTION) {
				return false;
			}
			placementComponent.cancelEdit();
			enableControls(false);
		}
		return true;
	}

	boolean apply(CompositeChangeListener listener) {
		boolean deleteConflicts = false;
		if (placementComponent.hasApplyConflict()) {
			long allocationSize = (Long) allocSizeModel.getValue();
			int option = OptionDialog.showOptionDialog(this, "Bitfield Conflict(s)",
				"Bitfield placement conflicts with one or more components.\n" +
					"Would you like to delete conflicts or move conflicts by " + allocationSize +
					" bytes?",
				"Delete Conflicts", "Move Conflicts", OptionDialog.WARNING_MESSAGE);
			if (option == OptionDialog.CANCEL_OPTION) {
				return false;
			}
			deleteConflicts = (option == OptionDialog.OPTION_ONE);
		}
		placementComponent.applyBitField(baseDataType, fieldNameTextField.getText().trim(),
			deleteConflicts, listener);
		enableControls(false);
		return true;
	}

	private void enableControls(boolean enable) {
		allocSizeInput.setEnabled(enable);
		bitSizeInput.setEnabled(enable);
		bitOffsetInput.setEnabled(enable);
		if (!enable) {
			// TODO: set placementComponent mode to NONE
			bitOffsetModel.setValue(0L);
			bitSizeModel.setValue(1L);
			fieldNameTextField.setText(null);
		}
	}

	private void setBitFieldOffset(Point point) {
		int bitOffset = placementComponent.getBitOffset(point);
		if (bitOffset >= 0) {
			// long cast is required for auto-box to Long object
			bitOffsetModel.setValue((long) bitOffset);
		}
	}

	private DataTypeComponent getDataTypeComponent(Point p) {
		BitAttributes attrs = placementComponent.getBitAttributes(p);
		if (attrs != null) {
			return attrs.getDataTypeComponent(true);
		}
		return null;
	}

	private void updateBitSizeModel() {
		int allocSize = allocSizeModel.getNumber().intValue();
		int allocBits = 8 * allocSize;
		int baseTypeBits = baseDataType != null ? (8 * baseDataType.getLength()) : allocBits;
		long maxBitSize = Math.min(allocBits, baseTypeBits);
		bitSizeModel.setMaximum(maxBitSize);
		if (maxBitSize < (Long) bitSizeModel.getValue()) {
			bitSizeModel.setValue(maxBitSize);
		}
	}

	private void update() {
		if (updating) {
			return;
		}
		updating = true;
		try {
			int allocSize = allocSizeModel.getNumber().intValue();
			int allocBits = 8 * allocSize;
			updateBitSizeModel();
			bitOffsetModel.setMaximum(Long.valueOf(allocBits - 1));
			int bitSize = bitSizeModel.getNumber().intValue();

			int boff = bitOffsetModel.getNumber().intValue();
			int total = bitSize + boff;
			if (total > allocBits) {
				boff -= total - allocBits;
				if (boff < 0) {
					boff = 0;
				}
			}
			if (bitSize == 0) {
				// force preferred placement of zero-length bit-field
				//   little-endian: lsb of byte
				//   big-endian: msb of byte
				boff = 8 * (boff / 8);
				if (placementComponent.isBigEndian()) {
					boff += 7;
				}
				bitOffsetModel.setStepSize((long) 8);
			}
			else {
				bitOffsetModel.setStepSize((long) 1);
			}
			bitOffsetModel.setValue(Long.valueOf(boff));
			if (bitSize > allocBits) {
				bitSize = allocBits;
				bitSizeModel.setValue(Long.valueOf(bitSize));
			}
			placementComponent.refresh(allocSize, bitSize, boff);
		}
		finally {
			updating = false;
		}
	}

	ActionContext getActionContext(MouseEvent event) {
		if (placementComponent == event.getSource()) {
			Point p = event.getPoint();
			return new BitFieldEditorContext(getDataTypeComponent(p),
				placementComponent.getBitOffset(p));
		}
		return null;
	}

	class BitFieldEditorContext extends ActionContext {

		private int selectedBitOffset;
		private DataTypeComponent selectedDtc;

		private BitFieldEditorContext(DataTypeComponent selectedDtc, int selectedBitOffset) {
			this.selectedDtc = selectedDtc;
			this.selectedBitOffset = selectedBitOffset;
		}

		DataTypeComponent getSelectedComponent() {
			return selectedDtc;
		}

		public int getAllocationOffset() {
			return placementComponent.getAllocationOffset();
		}

		public int getSelectedBitOffset() {
			return selectedBitOffset;
		}

	}

	private static class JSpinnerWithMouseWheel extends JSpinner implements MouseWheelListener {

		JSpinnerWithMouseWheel(SpinnerNumberModel model) {
			super(model);
			addMouseWheelListener(this);
		}

		@Override
		public void requestFocus() {
			DefaultEditor editor = (DefaultEditor) getEditor();
			editor.getTextField().requestFocus();
		}

		@Override
		public void mouseWheelMoved(MouseWheelEvent mwe) {
			if (!isEnabled()) {
				return;
			}
			if (mwe.getScrollType() != MouseWheelEvent.WHEEL_UNIT_SCROLL) {
				return;
			}
			SpinnerNumberModel m = (SpinnerNumberModel) getModel();
			if (mwe.getScrollType() != MouseWheelEvent.WHEEL_UNIT_SCROLL) {
				// TODO: Handle other mouse wheel modes
				return;
			}
			Long value =
				mwe.getUnitsToScroll() > 0 ? (Long) m.getPreviousValue() : (Long) m.getNextValue();
			if (value != null) {
				setValue(value);
				mwe.consume();
			}
		}
	}
}
