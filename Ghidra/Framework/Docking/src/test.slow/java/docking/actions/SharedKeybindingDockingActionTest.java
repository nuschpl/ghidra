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
package docking.actions;

import static org.junit.Assert.*;

import java.awt.event.KeyEvent;
import java.util.List;
import java.util.Set;

import javax.swing.KeyStroke;

import org.apache.commons.collections4.IterableUtils;
import org.junit.Before;
import org.junit.Test;

import docking.*;
import docking.action.*;
import docking.test.AbstractDockingTest;
import docking.tool.util.DockingToolConstants;
import ghidra.framework.options.ToolOptions;
import ghidra.util.Msg;
import ghidra.util.SpyErrorLogger;

public class SharedKeybindingDockingActionTest extends AbstractDockingTest {

	private static final String SHARED_NAME = "Shared Action Name";
	private static final String SHARED_OWNER = SharedStubKeyBindingAction.SHARED_OWNER;

	// format:  getName() + " (" + getOwner() + ")";
	private static final String SHARED_FULL_NAME = SHARED_NAME + " (" + SHARED_OWNER + ")";

	private static final KeyStroke DEFAULT_KS_1 = KeyStroke.getKeyStroke(KeyEvent.VK_A, 0);
	private static final KeyStroke DEFAULT_KS_DIFFERENT_THAN_1 =
		KeyStroke.getKeyStroke(KeyEvent.VK_B, 0);
	private static final String OWNER_1 = "Owner1";
	private static final String OWNER_2 = "Owner2";

	private SpyErrorLogger spyLogger = new SpyErrorLogger();

	private DockingTool tool;

	@Before
	public void setUp() {
		tool = new FakeDockingTool();

		Msg.setErrorLogger(spyLogger);
	}

	@Test
	public void testSharedKeyBinding_SameDefaultKeyBindings() {

		TestAction action1 = new TestAction(OWNER_1, DEFAULT_KS_1);
		TestAction action2 = new TestAction(OWNER_2, DEFAULT_KS_1);

		tool.addAction(action1);
		tool.addAction(action2);

		assertNoLoggedMessages();
		assertKeyBinding(action1, DEFAULT_KS_1);
		assertKeyBinding(action2, DEFAULT_KS_1);
	}

	@Test
	public void testSharedKeyBinding_OptionsChange() {

		TestAction action1 = new TestAction(OWNER_1, DEFAULT_KS_1);
		TestAction action2 = new TestAction(OWNER_2, DEFAULT_KS_1);

		tool.addAction(action1);
		tool.addAction(action2);

		KeyStroke newKs = KeyStroke.getKeyStroke(KeyEvent.VK_Z, 0);
		setSharedKeyBinding(newKs);

		assertNoLoggedMessages();
		assertKeyBinding(action1, newKs);
		assertKeyBinding(action2, newKs);
	}

	@Test
	public void testSharedKeyBinding_DifferentDefaultKeyBindings() {

		TestAction action1 = new TestAction(OWNER_1, DEFAULT_KS_1);
		TestAction action2 = new TestAction(OWNER_2, DEFAULT_KS_DIFFERENT_THAN_1);

		tool.addAction(action1);
		tool.addAction(action2);

		// both bindings should keep the first one that was set when they are different
		assertImproperDefaultBindingMessage();
		assertKeyBinding(action1, DEFAULT_KS_1);
		assertKeyBinding(action2, DEFAULT_KS_1);
	}

	@Test
	public void testSharedKeyBinding_NoDefaultKeyBindings() {

		TestAction action1 = new TestAction(OWNER_1, null);
		TestAction action2 = new TestAction(OWNER_2, null);

		tool.addAction(action1);
		tool.addAction(action2);

		// both bindings are null; this is allowed
		assertNoLoggedMessages();
		assertKeyBinding(action1, null);
		assertKeyBinding(action2, null);
	}

	@Test
	public void testSharedKeyBinding_OneDefaultOneUndefinedDefaultKeyBinding() {
		TestAction action1 = new TestAction(OWNER_1, DEFAULT_KS_1);
		TestAction action2 = new TestAction(OWNER_2, null);

		tool.addAction(action1);
		tool.addAction(action2);

		// both bindings should keep the first one that was set when they are different
		assertImproperDefaultBindingMessage();
		assertKeyBinding(action1, DEFAULT_KS_1);
		assertKeyBinding(action2, DEFAULT_KS_1);
	}

	@Test
	public void testSharedKeyBinding_RemoveAction() {

		TestAction action1 = new TestAction(OWNER_1, DEFAULT_KS_1);
		TestAction action2 = new TestAction(OWNER_2, DEFAULT_KS_1);

		tool.addAction(action1);
		tool.addAction(action2);

		tool.removeAction(action1);

		assertActionNotInTool(action1);
		assertActionInTool(action2);

		tool.removeAction(action2);
		assertActionNotInTool(action2);

		String sharedName = action1.getFullName();
		assertNoSharedKeyBindingStubInstalled(sharedName);
	}

	@Test
	public void testSharedKeyBinding_AddSameActionTwice() {

		TestAction action1 = new TestAction(OWNER_1, DEFAULT_KS_1);

		tool.addAction(action1);
		tool.addAction(action1);

		assertOnlyOneVersionOfActionInTool(action1);

		assertNoLoggedMessages();
		assertKeyBinding(action1, DEFAULT_KS_1);
	}

	@Test
	public void testSharedKeyBinding_OnlyOneEntryInOptions() {

		TestAction action1 = new TestAction(OWNER_1, DEFAULT_KS_1);
		TestAction action2 = new TestAction(OWNER_2, DEFAULT_KS_1);

		tool.addAction(action1);
		tool.addAction(action2);

		// verify that the actions are not in the options, but that the shared action is
		ToolOptions keyOptions = tool.getOptions(DockingToolConstants.KEY_BINDINGS);
		List<String> names = keyOptions.getOptionNames();
		assertTrue(names.contains(SHARED_FULL_NAME));
		assertFalse(names.contains(action1.getFullName()));
		assertFalse(names.contains(action2.getFullName()));
	}

	@Test
	public void testSharedKeyBinding_AddActionAfterOptionHasChanged() {

		TestAction action1 = new TestAction(OWNER_1, DEFAULT_KS_1);
		TestAction action2 = new TestAction(OWNER_2, DEFAULT_KS_1);

		tool.addAction(action1);
		KeyStroke newKs = KeyStroke.getKeyStroke(KeyEvent.VK_Z, 0);
		setSharedKeyBinding(newKs);

		assertKeyBinding(action1, newKs);

		// verify the newly added keybinding gets the newly changed option
		tool.addAction(action2);
		assertKeyBinding(action1, newKs);
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private void assertOnlyOneVersionOfActionInTool(TestAction action) {
		Set<DockingActionIf> actions = getActions(tool, action.getName());
		assertEquals("There should be only one instance of this action in the tool: " + action, 1,
			actions.size());
	}

	private void assertActionInTool(TestAction action) {

		Set<DockingActionIf> actions = getActions(tool, action.getName());
		for (DockingActionIf toolAction : actions) {
			if (toolAction == action) {
				return;
			}
		}

		fail("Action is not in the tool: " + action);
	}

	private void assertActionNotInTool(TestAction action) {
		Set<DockingActionIf> actions = getActions(tool, action.getName());
		for (DockingActionIf toolAction : actions) {
			assertNotSame(toolAction, action);
		}
	}

	private void assertNoSharedKeyBindingStubInstalled(String sharedName) {

		List<DockingActionIf> actions = tool.getDockingActionsByFullActionName(sharedName);
		assertTrue("There should be no actions registered for '" + sharedName + "'",
			actions.isEmpty());
	}

	private void setSharedKeyBinding(KeyStroke newKs) {
		ToolOptions options = getKeyBindingOptions();
		runSwing(() -> options.setKeyStroke(SHARED_FULL_NAME, newKs));
		waitForSwing();
	}

	private ToolOptions getKeyBindingOptions() {
		return tool.getOptions(DockingToolConstants.KEY_BINDINGS);
	}

	private void assertNoLoggedMessages() {
		assertTrue("Spy logger not empty: " + spyLogger, IterableUtils.isEmpty(spyLogger));
	}

	private void assertImproperDefaultBindingMessage() {
		spyLogger.assertLogMessage("shared", "key", "binding", "action", "different", "default");
	}

	private void assertKeyBinding(TestAction action, KeyStroke expectedKs) {
		assertEquals(expectedKs, action.getKeyBinding());
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class TestAction extends DockingAction {

		public TestAction(String owner, KeyStroke ks) {
			super(SHARED_NAME, owner);

			if (ks != null) {
				setKeyBindingData(new KeyBindingData(ks));
			}
		}

		@Override
		public boolean usesSharedKeyBinding() {
			return true;
		}

		@Override
		public void actionPerformed(ActionContext context) {
			fail("Action performed should not have been called");
		}
	}
}
