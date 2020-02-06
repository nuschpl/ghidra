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

import static org.junit.Assert.*;

import java.awt.BorderLayout;

import javax.swing.*;

import org.junit.*;

import docking.widgets.table.model.TestDataModel;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.Msg;
import ghidra.util.table.GhidraTable;

public class GTableTest extends AbstractGhidraHeadedIntegrationTest {
	private TestDataModel model;
	private GhidraTable table;
	private JFrame frame;
	private long testKeyTimeout = 100;

	@Before
	public void setUp() throws Exception {
		model = new TestDataModel();
		table = new GhidraTable(model);
		table.setAutoLookupTimeout(testKeyTimeout);

		frame = new JFrame("Ghidra Table Test");
		frame.getContentPane().setLayout(new BorderLayout());
		frame.getContentPane().add(new JScrollPane(table));
		frame.pack();
		frame.setVisible(true);

		// showing the table will trigger a call to sort; wait for sorting to finish
		waitForSort();
	}

	@After
	public void tearDown() throws Exception {
		frame.dispose();
	}

	@Test
	public void testAutoLookup() throws Exception {

		table.setAutoLookupColumn(4);

		setSelectedRow(table, 0);

		triggerText(table, "a");
		assertSelectedRow(11, "a");

		triggerText(table, "c");
		assertSelectedRow(12, "c");
		timeout();

		triggerText(table, "ad");
		assertSelectedRow(24, "ad");
		timeout();

		triggerText(table, "av");
		assertSelectedRow(70, "av");
		timeout();

		triggerText(table, "x");
		assertSelectedRow(1920, "x");
		timeout();

		triggerText(table, "a");
		assertSelectedRow(11, "a");

		// test the case where no match is found
		table.setAutoLookupTimeout(1000); // longer timeout needed for multiple keys
		triggerText(table, "zed");
		assertSelectedRow(11, "zed"); // no change
	}

	@Test
	public void testAutoLookup_SortDescending() throws Exception {

		int column = 4;
		sortDescending(column);

		table.setAutoLookupColumn(column);

		setSelectedRow(table, 0);

		triggerText(table, "a");
		assertSelectedRow(1846, "a");

		triggerText(table, "c");
		assertSelectedRow(1902, "c");

		timeout();
		triggerText(table, "ad");
		assertSelectedRow(1885, "ad");

		timeout();
		triggerText(table, "av");
		assertSelectedRow(1848, "av");

		timeout();
		triggerText(table, "x");
		assertSelectedRow(0, "x");

		timeout();
		triggerText(table, "a");
		assertSelectedRow(1846, "a");

		// test the case where no match is found
		table.setAutoLookupTimeout(1000); // longer timeout needed for multiple keys
		triggerText(table, "zed");
		assertSelectedRow(1846, "zed"); // no change
	}

	@Test
	public void testAutoLookup_WhenColumnIsNotSorted() throws Exception {

		int column = 4;
		removeSortColumn(column);

		table.setAutoLookupColumn(column);

		setSelectedRow(table, 0);

		// note: the order checked here is the same as the sorted order, since we did not move
		//       any rows after disabling the sort
		triggerText(table, "a");
		assertSelectedRow(11, "a");

		triggerText(table, "c");
		assertSelectedRow(12, "c");
		timeout();

		triggerText(table, "ad");
		assertSelectedRow(24, "ad");
		timeout();

		triggerText(table, "av");
		assertSelectedRow(70, "av");
		timeout();

		triggerText(table, "x");
		assertSelectedRow(1920, "x");
		timeout();

		triggerText(table, "a");
		assertSelectedRow(11, "a");

		// test the case where no match is found
		table.setAutoLookupTimeout(1000); // longer timeout needed for multiple keys
		triggerText(table, "zed");
		assertSelectedRow(11, "zed"); // no change
	}

	@Test
	public void testSetActionsEnabled() throws Exception {

		table.setAutoLookupColumn(4);
		assertFalse(table.areActionsEnabled());
		setSelectedRow(table, 0);

		triggerText(table, "a");
		assertEquals("Auto-lookup failed to change the table row", 11, table.getSelectedRow());

		// this will disable 'auto lookup'
		table.setActionsEnabled(true);
		setSelectedRow(table, 0);

		triggerText(table, "a");
		assertEquals("Auto-lookup should be disabled when actions are enabled", 0,
			table.getSelectedRow());

		table.setActionsEnabled(false);
		setSelectedRow(table, 0);

		triggerText(table, "a");
		assertEquals("Auto-lookup failed to change the table row", 11, table.getSelectedRow());

		table.setActionsEnabled(true);
		setSelectedRow(table, 0);

		triggerText(table, "a");
		assertEquals("Auto-lookup should be disabled when actions are enabled", 0,
			table.getSelectedRow());

		table.setAutoLookupColumn(4);
		setSelectedRow(table, 0);

		triggerText(table, "a");
		assertEquals("Auto-lookup failed to change the table row", 11, table.getSelectedRow());
	}

	private void assertSelectedRow(int row, String lookupText) {

		int actual = runSwing(() -> table.getSelectedRow());
		if (row != actual) {

			int col = 4; // String 'Name' column
			String expectedString = (String) table.getValueAt(row, col);
			String actualString = (String) table.getValueAt(actual, col);
			String message = "Auto-lookup row not selected for '" + lookupText + "'.\n\t" +
				"Expected text: '" + expectedString + "'; Actual text: '" + actualString + "'";
			Msg.out(message);
			assertEquals(message, row, actual);
		}
	}

	private void removeSortColumn(int column) {
		waitForSwing();
		runSwing(() -> TableUtils.columnAlternativelySelected(table, column));
		waitForSort();
	}

	private void waitForSort() {
		// the call to sort may be run in an invokeLater()
		waitForSwing();
		waitForCondition(() -> !model.isSortPending());
		waitForSwing();
	}

	private void sortDescending(int column) {

		TableSortState descendingSortState = TableSortState.createDefaultSortState(column, false);
		runSwing(() -> model.setTableSortState(descendingSortState));
		waitForSort();
	}

	private void timeout() {
		sleep(testKeyTimeout * 2);
	}

	private void setSelectedRow(final GhidraTable table, final int i) throws Exception {
		SwingUtilities.invokeAndWait(() -> table.setRowSelectionInterval(i, i));
		waitForPostedSwingRunnables();
	}

}
