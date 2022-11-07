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
package docking.widgets.table;

import java.awt.*;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.text.DecimalFormat;
import java.util.HashMap;
import java.util.Map;

import javax.swing.JTable;
import javax.swing.SwingConstants;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableModel;

import docking.widgets.AbstractGCellRenderer;
import generic.theme.GColor;
import generic.theme.Gui;
import ghidra.docking.settings.*;
import ghidra.util.*;
import ghidra.util.exception.AssertException;

/**
 * A default table cell renderer that relies on the <code>toString()</code> method
 * when rendering the cells of the table.
 */
public class GTableCellRenderer extends AbstractGCellRenderer implements TableCellRenderer {

	protected static final FormatSettingsDefinition INTEGER_RADIX_SETTING =
		FormatSettingsDefinition.DEF_DECIMAL;

	protected static final IntegerSignednessFormattingModeSettingsDefinition INTEGER_SIGNEDNESS_MODE_SETTING =
		IntegerSignednessFormattingModeSettingsDefinition.DEF;

	protected static final FloatingPointPrecisionSettingsDefinition FLOATING_POINT_PRECISION_SETTING =
		FloatingPointPrecisionSettingsDefinition.DEF;

	private static final Color BG_DRAG = new GColor("color.bg.table.row.drag");

	private static DecimalFormat decimalFormat;
	private static Map<Integer, DecimalFormat> decimalFormatCache;

	/**
	 * Constructs a new GTableCellRenderer.
	 */
	public GTableCellRenderer() {
		// When the Look And Feel changes, renderers are not auto updated because they
		// are not part of the component tree. So listen for a change to the Look And Feel.
		Gui.addThemeListener(e -> {
			if (e.isLookAndFeelChanged()) {
				updateUI();
			}
		});
	}

	/**
	 * Constructs a new GTableCellRenderer using the specified font.
	 * @param f the font to use when rendering text in the table cells
	 */
	public GTableCellRenderer(Font f) {
		this();
		setFont(f);
	}

	/**
	 * Return the cell renderer text
	 * @param value Cell object value
	 * @return A string interpretation of value; generated by calling value.toString()
	 */
	protected String getText(Object value) {
		return value == null ? "" : value.toString();
	}

	/**
	 * Satisfies the Java {@link javax.swing.table.TableCellRenderer} interface; retrieves
	 * column data via a GTableCellRenderingData object, and defers painting to
	 * {@link #getTableCellRendererComponent(GTableCellRenderingData)}.
	 * <p>
	 * This is marked <code>final</code> to redirect subclasses to the enhanced method,
	 * {@link #getTableCellRendererComponent(GTableCellRenderingData)}.
	 * <p>
	 * Throws an AssertException if the table this renderer is used with is not a
	 * {@link docking.widgets.table.GTable} instance.
	 *
	 *  @see javax.swing.table.TableCellRenderer#getTableCellRendererComponent(javax.swing.JTable, java.lang.Object, boolean, boolean, int, int)
	 *  @see #getTableCellRendererComponent(GTableCellRenderingData)
	 */
	@Override
	public final Component getTableCellRendererComponent(JTable table, Object value,
			boolean isSelected, boolean hasFocus, int row, int column) {

		if (!(table instanceof GTable)) {
			throw new AssertException(
				"Using a GTableCellRenderer in a non-GTable table. (Model class: " +
					table.getModel().getClass().getName() + ")");
		}

		GTable gTable = (GTable) table;
		GTableCellRenderingData data = gTable.getRenderingData(column);
		Object rowObject = null;

		if (gTable.getModel() instanceof RowObjectTableModel) {
			rowObject = ((RowObjectTableModel<?>) gTable.getModel()).getRowObject(row);
		}

		data.setRowData(row, rowObject);
		data.setCellData(value, column, isSelected, hasFocus);

		Component renderComponent = getTableCellRendererComponent(data);

		data.resetRowData();

		return renderComponent;
	}

	/**
	 * Provide basic cell rendering -- setting foreground and background colors, font, text,
	 * alignment, drop color, and border. Additional data that may be of use to the renderer
	 * is passed through the {@link docking.widgets.table.GTableCellRenderingData} object.
	 * @param data Context data used in the rendering of a data cell.
	 * @return The component used for drawing the table cell.
	 */
	public Component getTableCellRendererComponent(GTableCellRenderingData data) {

		Object value = data.getValue();
		JTable table = data.getTable();
		int row = data.getRowViewIndex();
		int column = data.getColumnViewIndex();
		boolean isSelected = data.isSelected();
		boolean hasFocus = data.hasFocus();
		Settings settings = data.getColumnSettings();

		if (value instanceof Number) {
			setHorizontalAlignment(SwingConstants.RIGHT);
			setText(formatNumber((Number) value, settings));
		}
		else {
			setText(getText(value));
			setHorizontalAlignment(SwingConstants.LEFT);
		}

		TableModel model = table.getModel();
		configureFont(table, model, column);

		if (isSelected) {
			setForeground(table.getSelectionForeground());
			setBackground(table.getSelectionBackground());
			setOpaque(true);
		}
		else {
			setForegroundColor(table, model, value);

			if (row == dropRow) {
				setBackground(BG_DRAG);
			}
			else {
				setBackground(getOSDependentBackgroundColor(table, row));
			}
		}

		setBorder(hasFocus ? focusBorder : noFocusBorder);
		return this;
	}

	protected void setForegroundColor(JTable table, TableModel model, Object value) {
		setForeground(table.getForeground());
	}

	protected void configureFont(JTable table, TableModel model, int column) {
		setFont(defaultFont);
	}

	/**
	 * Format a Number per the Settings parameters.
	 * @param value the number to format
	 * @param settings settings controlling the display of the Number parameter
	 * @return a formatted representation of the Number value
	 */
	protected String formatNumber(Number value, Settings settings) {
		String numberString = value.toString();

		if (NumericUtilities.isIntegerType(value)) {
			int radix = INTEGER_RADIX_SETTING.getRadix(settings);
			SignednessFormatMode signMode = INTEGER_SIGNEDNESS_MODE_SETTING.getFormatMode(settings);

			long number = value.longValue();
			numberString = NumericUtilities.formatNumber(number, radix, signMode);

		}
		else if (NumericUtilities.isFloatingPointType(value)) {
			Double number = value.doubleValue();
			if (number.isNaN() || number.isInfinite()) {
				numberString = Character.toString('\u221e'); // infinity symbol
			}
			else {
				int digitsPrecision = FLOATING_POINT_PRECISION_SETTING.getPrecision(settings);
				numberString = getFormatter(digitsPrecision).format(number);
			}
		}
		else if (value instanceof BigInteger) {
			int radix = INTEGER_RADIX_SETTING.getRadix(settings);
			numberString = ((BigInteger) value).toString(radix);
		}
		else if (value instanceof BigDecimal) {
			numberString = ((BigDecimal) value).toPlainString();
		}
		return numberString;
	}

	private DecimalFormat getFormatter(int digitsPrecision) {
		if (decimalFormat == null) {
			initFormatCache();
		}

		digitsPrecision = Math.max(0,
			Math.min(digitsPrecision, FloatingPointPrecisionSettingsDefinition.MAX_PRECISION));

		return decimalFormatCache.get(digitsPrecision);
	}

	private static void initFormatCache() {
		decimalFormatCache = new HashMap<>(FloatingPointPrecisionSettingsDefinition.MAX_PRECISION);
		for (int i = 0; i <= FloatingPointPrecisionSettingsDefinition.MAX_PRECISION; i++) {
			decimalFormatCache.put(i, new DecimalFormat(createDecimalFormat(i)));
		}
	}

	private static String createDecimalFormat(int digitsPrecision) {
		if (digitsPrecision <= 0) {
			return "0";
		}
		return "0." + StringUtilities.pad("", '0', digitsPrecision);
	}
}
