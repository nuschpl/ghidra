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
package docking.theme.gui;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.event.*;
import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

import javax.swing.*;
import javax.swing.table.TableColumn;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import docking.theme.*;
import docking.widgets.OptionDialog;
import docking.widgets.combobox.GhidraComboBox;
import docking.widgets.dialogs.InputDialog;
import docking.widgets.table.GFilterTable;
import docking.widgets.table.GTable;
import ghidra.framework.Application;
import ghidra.util.Msg;
import ghidra.util.Swing;
import resources.Icons;

public class ThemeDialog extends DialogComponentProvider {
	private static ThemeDialog INSTANCE;
	private ThemeColorTableModel colorTableModel;
	private ThemeColorEditorDialog dialog;

	// stores the original value for ids whose value has changed
	private GThemeValueMap changedValuesMap = new GThemeValueMap();
	private JButton saveButton;
	private JButton restoreButton;
	private GhidraComboBox<String> combo;
	private ItemListener comboListener = this::themeComboChanged;

	public ThemeDialog() {
		super("Theme Dialog", false);
		addWorkPanel(createMainPanel());

		addDismissButton();
		addButton(createSaveButton());
		addButton(createRestoreButton());

		setPreferredSize(1100, 500);
		setRememberSize(false);
		updateButtons();
	}

	@Override
	protected void dismissCallback() {
		if (hasChanges()) {
			int result = OptionDialog.showYesNoCancelDialog(null, "Close Theme Dialog",
				"You have changed the theme.\n Do you want save your changes?");
			if (result == OptionDialog.CANCEL_OPTION) {
				return;
			}
			if (result == OptionDialog.YES_OPTION) {
				if (!save()) {
					return;
				}
			}
			else {
				Gui.reloadGhidraDefaults();
			}
		}
		INSTANCE = null;
		close();
	}

	protected void saveCallback() {
		save();
		updateCombo();
	}

	private void restoreCallback() {
		if (hasChanges()) {
			int result = OptionDialog.showYesNoDialog(null, "Restore Theme Values",
				"Are you sure you want to discard all your changes?");
			if (result == OptionDialog.NO_OPTION) {
				return;
			}
		}
		Gui.restoreThemeValues();
		reset();
	}

	private void reloadDefaultsCallback(ActionEvent e) {
		if (hasChanges()) {
			int result = OptionDialog.showYesNoDialog(null, "Reload Ghidra Default Values",
				"This will discard all your theme changes. Continue?");
			if (result == OptionDialog.NO_OPTION) {
				return;
			}
		}
		Gui.reloadGhidraDefaults();
		reset();
	}

	private void reset() {
		changedValuesMap.clear();
		colorTableModel.reloadAll();
		updateButtons();
	}

	/**
	 * Saves all current theme changes
	 * @return true if the operation was not cancelled.
	 */
	private boolean save() {
		GTheme activeTheme = Gui.getActiveTheme();
		if (activeTheme instanceof FileGTheme) {
			FileGTheme fileTheme = (FileGTheme) activeTheme;
			if (fileTheme.canSave()) {
				int result = OptionDialog.showYesNoCancelDialog(null, "Overwrite Existing Theme",
					"Do you want to overwrite the existing theme file?");
				if (result == OptionDialog.CANCEL_OPTION) {
					return false;
				}
				if (result == OptionDialog.YES_OPTION) {
					return saveCurrentValuesToTheme(fileTheme, false);
				}
			}
		}
		// save to new Theme file

		InputDialog inputDialog = new InputDialog("Create Theme", "New Theme Name");
		DockingWindowManager.showDialog(inputDialog);
		String themeName = inputDialog.getValue();
		if (themeName == null) {
			return false;
		}
		File file = getSaveFile(themeName);
		LafType laf = activeTheme.getLookAndFeelType();
		return saveCurrentValuesToTheme(new FileGTheme(file, themeName, laf), false);
	}

	private boolean saveCurrentValuesToTheme(FileGTheme newTheme, boolean includeDefaults) {
		newTheme.clear();
		GThemeValueMap allValues = Gui.getAllValues();
		if (includeDefaults) {
			newTheme.load(allValues);
		}
		else {
			Gui.getAllValues();
			newTheme.load(allValues.removeSameValues(Gui.getDefaults()));
		}
		try {
			newTheme.save();
			Gui.addTheme(newTheme);
			Gui.setTheme(newTheme);
		}
		catch (IOException e) {
			Msg.showError(this, null, "I/O Error",
				"Error writing theme file: " + newTheme.getFile().getAbsolutePath(), e);
			return false;
		}

		return true;

	}

	private File getSaveFile(String themeName) {
		File dir = Application.getUserSettingsDirectory();
		String cleanedName = themeName.replaceAll(" ", "_") + GTheme.FILE_EXTENSION;
		return new File(dir, cleanedName);
	}

//	private void export() {
//		GhidraFileChooser chooser = new GhidraFileChooser(getComponent());
//		chooser.setTitle("Choose Theme File");
//		chooser.setApproveButtonText("Select Output File");
//		chooser.setApproveButtonToolTipText("Select File");
//		chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
//		chooser.setSelectedFileFilter(GhidraFileFilter.ALL);
//		File file = chooser.getSelectedFile();
//		try {
//			Gui.getActiveTheme().saveToFile(file, Gui.getDefaults());
//			return true;
//		}
//		catch (IOException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
//		return false;
//	}

	private void themeComboChanged(ItemEvent e) {
		if (e.getStateChange() == ItemEvent.SELECTED) {
			String themeName = (String) e.getItem();
			if (hasChanges()) {
				Msg.debug(this, "has changes");
			}
			Swing.runLater(() -> {
				Gui.setTheme(Gui.getTheme(themeName));
				changedValuesMap.clear();
				colorTableModel.reloadAll();
			});
		}
	}

	private boolean hasChanges() {
		return !changedValuesMap.isEmpty();
	}

	protected void editColor(ColorValue value) {
		if (dialog == null) {
			dialog = new ThemeColorEditorDialog(this);
		}
		dialog.editColor(value);
	}

	void colorChanged(ColorValue oldValue, ColorValue newValue) {
		updateChanagedValueMap(oldValue, newValue);
		// run later - don't rock the boat in the middle of a listener callback
		Swing.runLater(() -> {
			Gui.setColor(newValue);
			colorTableModel.reloadCurrent();
		});
	}

	private void updateChanagedValueMap(ColorValue oldValue, ColorValue newValue) {
		ColorValue originalValue = changedValuesMap.getColor(oldValue.getId());
		if (originalValue == null) {
			changedValuesMap.addColor(oldValue);
		}
		else if (originalValue.equals(newValue)) {
			// if restoring the original color, remove it from the map of changes
			changedValuesMap.removeColor(oldValue.getId());
		}
		updateButtons();
	}

	private void updateButtons() {
		boolean hasChanges = hasChanges();
		saveButton.setEnabled(hasChanges);
		restoreButton.setEnabled(hasChanges);
	}

	void colorEditorClosed() {
		dialog = null;
	}

	private JComponent createMainPanel() {
		JPanel panel = new JPanel();

		panel.setLayout(new BorderLayout());
		panel.add(buildControlPanel(), BorderLayout.NORTH);
		panel.add(buildTabedTables());
		return panel;
	}

	private Component buildControlPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		panel.add(buildThemeCombo(), BorderLayout.WEST);
		panel.add(buildReloadDefaultsButton(), BorderLayout.EAST);
		panel.setName("gthemePanel");
		return panel;
	}

	private Component buildReloadDefaultsButton() {
		JButton button = new JButton(Icons.REFRESH_ICON);
		button.addActionListener(this::reloadDefaultsCallback);
		button.setToolTipText(
			"Reload Ghidra Defaults (Only needed if you change a theme.properties file)");
		return button;
	}

	private void updateCombo() {
		Set<GTheme> supportedThemes = Gui.getSupportedThemes();
		List<String> themeNames =
			supportedThemes.stream().map(t -> t.getName()).collect(Collectors.toList());
		Collections.sort(themeNames);
		combo.removeItemListener(comboListener);
		combo.setModel(new DefaultComboBoxModel<String>(new Vector<String>(themeNames)));
		combo.setSelectedItem(Gui.getActiveTheme().getName());
		combo.addItemListener(comboListener);
	}

	private Component buildThemeCombo() {
		JPanel panel = new JPanel();
		Set<GTheme> supportedThemes = Gui.getSupportedThemes();
		List<String> themeNames =
			supportedThemes.stream().map(t -> t.getName()).collect(Collectors.toList());
		Collections.sort(themeNames);

		combo = new GhidraComboBox<>(themeNames);
		combo.setSelectedItem(Gui.getActiveTheme().getName());
		combo.addItemListener(comboListener);

		panel.add(new JLabel("Theme: "), BorderLayout.WEST);
		panel.add(combo);
		panel.setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 10));
		return panel;
	}

	private Component buildTabedTables() {
		JTabbedPane tabbedPane = new JTabbedPane();
		tabbedPane.add("Colors", buildColorTable());
		return tabbedPane;
	}

	private JComponent buildColorTable() {
		colorTableModel = new ThemeColorTableModel();

		GFilterTable<ColorValue> filterTable = new GFilterTable<>(colorTableModel);
		GTable table = filterTable.getTable();
		table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

		table.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() == KeyEvent.VK_ENTER) {
					ColorValue colorValue = filterTable.getSelectedRowObject();
					if (colorValue != null) {
						editColor(colorValue);
					}
					e.consume();
				}
			}
		});

		table.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() == 2) {
					ColorValue value = filterTable.getItemAt(e.getPoint());
					Object cellValue = filterTable.getCellValue(e.getPoint());
//					editColor(value);

					int col = filterTable.getColumn(e.getPoint());
					TableColumn column = table.getColumnModel().getColumn(col);
					Object identifier = column.getIdentifier();
					if ("Current Color".equals(identifier) || "Id".equals(identifier)) {
						editColor(value);
					}
				}
			}
		});

		return filterTable;
	}

	private JButton createRestoreButton() {
		restoreButton = new JButton("Restore");
		restoreButton.setMnemonic('R');
		restoreButton.setName("Restore");
		restoreButton.addActionListener(e -> restoreCallback());
		restoreButton.setToolTipText("Restores all values to current theme");
		return restoreButton;
	}

	private JButton createSaveButton() {
		saveButton = new JButton("Save");
		saveButton.setMnemonic('S');
		saveButton.setName("Save");
		saveButton.addActionListener(e -> saveCallback());
		saveButton.setToolTipText("Saves changed values to a new Theme");
		return saveButton;
	}

	public static void editTheme() {
		if (INSTANCE != null) {
			INSTANCE.toFront();
			return;
		}
		INSTANCE = new ThemeDialog();
		DockingWindowManager.showDialog(INSTANCE);

	}

}
