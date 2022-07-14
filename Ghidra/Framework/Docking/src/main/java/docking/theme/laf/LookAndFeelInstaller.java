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
package docking.theme.laf;

import java.awt.Color;
import java.awt.Font;
import java.util.*;
import java.util.Map.Entry;

import javax.swing.*;
import javax.swing.UIManager.LookAndFeelInfo;
import javax.swing.plaf.UIResource;

import docking.theme.*;
import ghidra.docking.util.LookAndFeelUtils;
import ghidra.util.*;

public abstract class LookAndFeelInstaller {

	public void install() throws Exception {
		cleanUiDefaults();
		installLookAndFeel();
		installJavaDefaults();
		fixupLookAndFeelIssues();
		installGlobalProperties();
	}

	private void installGlobalProperties() {
		installGlobalLookAndFeelAttributes();
		installGlobalFontSizeOverride();
		installCustomLookAndFeelActions();
		installPopupMenuSettingsOverride();
	}

	public abstract boolean isSupportedForCurrentPlatform();

	protected abstract void installLookAndFeel() throws Exception;

	protected void fixupLookAndFeelIssues() {
		// no generic fix-ups at this time.
	}

	protected void installJavaDefaults() {
		GThemeValueMap javaDefaults = extractJavaDefaults();
		Gui.setJavaDefaults(javaDefaults);
		installIndirectValues(javaDefaults);
	}

	private void installIndirectValues(GThemeValueMap javaDefaults) {
		UIDefaults defaults = UIManager.getDefaults();
		for (ColorValue colorValue : javaDefaults.getColors()) {
			String id = colorValue.getId();
			GColorUIResource gColor = Gui.getGColorUiResource(id);
			defaults.put(id, gColor);
		}
		for (FontValue fontValue : javaDefaults.getFonts()) {
			String id = fontValue.getId();
			GFont gFont = new GFont(id);
			if (!gFont.equals(fontValue.getRawValue())) {
				// only update if we have changed the default java color
				defaults.put(id, gFont);
			}
		}
	}

	protected GThemeValueMap extractJavaDefaults() {
		GThemeValueMap values = new GThemeValueMap();
		// for now, just doing color properties.
		List<String> ids =
			LookAndFeelUtils.getLookAndFeelIdsForType(UIManager.getDefaults(), Color.class);
		for (String id : ids) {
			values.addColor(new ColorValue(id, getNonUiColor(id)));
		}
		return values;
	}

	private static Color getNonUiColor(String id) {
		// Not sure, but for now, make sure colors are not UIResource
		Color color = UIManager.getColor(id);
		if (color instanceof UIResource) {
			return new Color(color.getRGB(), true);
		}
		return color;
	}

	private void cleanUiDefaults() {
		GThemeValueMap javaDefaults = Gui.getJavaDefaults();
		if (javaDefaults == null) {
			return;
		}
		UIDefaults defaults = UIManager.getDefaults();
		for (ColorValue colorValue : javaDefaults.getColors()) {
			String id = colorValue.getId();
			defaults.put(id, null);
		}
//		for (FontValue fontValue : javaDefaults.getFonts()) {
//			String id = fontValue.getId();
//			defaults.put(id, null);
//		}
	}

	protected String findLookAndFeelClassName(String lookAndFeelName) {
		LookAndFeelInfo[] installedLookAndFeels = UIManager.getInstalledLookAndFeels();
		for (LookAndFeelInfo info : installedLookAndFeels) {
			String className = info.getClassName();
			if (lookAndFeelName.equals(className) || lookAndFeelName.equals(info.getName())) {
				return className;
			}
		}

		Msg.debug(LookAndFeelUtils.class,
			"Unable to find requested Look and Feel: " + lookAndFeelName);
		return UIManager.getSystemLookAndFeelClassName();
	}

	protected boolean isSupported(String lookAndFeelName) {
		LookAndFeelInfo[] installedLookAndFeels = UIManager.getInstalledLookAndFeels();
		for (LookAndFeelInfo info : installedLookAndFeels) {
			if (lookAndFeelName.equals(info.getName())) {
				return true;
			}
		}
		return false;
	}

	protected void setKeyBinding(String existingKsText, String newKsText, String[] prefixValues) {

		KeyStroke existingKs = KeyStroke.getKeyStroke(existingKsText);
		KeyStroke newKs = KeyStroke.getKeyStroke(newKsText);

		for (String properyPrefix : prefixValues) {

			UIDefaults defaults = UIManager.getDefaults();
			Object object = defaults.get(properyPrefix + ".focusInputMap");
			InputMap inputMap = (InputMap) object;
			Object action = inputMap.get(existingKs);
			inputMap.put(newKs, action);
		}
	}

	private void installGlobalLookAndFeelAttributes() {
		// Fix up the default fonts that Java 1.5.0 changed to Courier, which looked terrible.
		Font f = new Font("Monospaced", Font.PLAIN, 12);
		UIManager.put("PasswordField.font", f);
		UIManager.put("TextArea.font", f);

		// We like buttons that change on hover, so force that to happen (see Tracker SCR 3966)
		UIManager.put("Button.rollover", Boolean.TRUE);
		UIManager.put("ToolBar.isRollover", Boolean.TRUE);
	}

	private void installPopupMenuSettingsOverride() {
		// Java 1.6 UI consumes MousePressed event when dismissing popup menu
		// which prevents application components from getting this event.
		UIManager.put("PopupMenu.consumeEventOnClose", Boolean.FALSE);
	}

	private void installGlobalFontSizeOverride() {

		// only set a global size if the property is set
		Integer overrideFontInteger = SystemUtilities.getFontSizeOverrideValue();
		if (overrideFontInteger == null) {
			return;
		}

		setGlobalFontSizeOverride(overrideFontInteger);
	}

	private void installCustomLookAndFeelActions() {
		// these prefixes are for text components
		String[] UIPrefixValues =
			{ "TextField", "FormattedTextField", "TextArea", "TextPane", "EditorPane" };

		DeleteToStartOfWordAction deleteToStartOfWordAction = new DeleteToStartOfWordAction();
		registerAction(deleteToStartOfWordAction, DeleteToStartOfWordAction.KEY_STROKE,
			UIPrefixValues);

		DeleteToEndOfWordAction deleteToEndOfWordAction = new DeleteToEndOfWordAction();
		registerAction(deleteToEndOfWordAction, DeleteToEndOfWordAction.KEY_STROKE, UIPrefixValues);

		BeginningOfLineAction beginningOfLineAction = new BeginningOfLineAction();
		registerAction(beginningOfLineAction, BeginningOfLineAction.KEY_STROKE, UIPrefixValues);

		EndOfLineAction endOfLineAction = new EndOfLineAction();
		registerAction(endOfLineAction, EndOfLineAction.KEY_STROKE, UIPrefixValues);

		SelectBeginningOfLineAction selectBeginningOfLineAction = new SelectBeginningOfLineAction();
		registerAction(selectBeginningOfLineAction, SelectBeginningOfLineAction.KEY_STROKE,
			UIPrefixValues);

		SelectEndOfLineAction selectEndOfLineAction = new SelectEndOfLineAction();
		registerAction(selectEndOfLineAction, SelectEndOfLineAction.KEY_STROKE, UIPrefixValues);
	}

	/** Allows you to globally set the font size (don't use this method!) */
	private void setGlobalFontSizeOverride(int fontSize) {
		UIDefaults defaults = UIManager.getDefaults();

		Set<Entry<Object, Object>> set = defaults.entrySet();
		Iterator<Entry<Object, Object>> iterator = set.iterator();
		while (iterator.hasNext()) {
			Entry<Object, Object> entry = iterator.next();
			Object key = entry.getKey();

			if (key.toString().toLowerCase().indexOf("font") != -1) {
				Font currentFont = defaults.getFont(key);
				if (currentFont != null) {
					Font newFont = currentFont.deriveFont((float) fontSize);
					UIManager.put(key, newFont);
				}
			}
		}
	}

	private void registerAction(Action action, KeyStroke keyStroke, String[] prefixValues) {
		for (String properyPrefix : prefixValues) {
			UIDefaults defaults = UIManager.getDefaults();
			Object object = defaults.get(properyPrefix + ".focusInputMap");
			InputMap inputMap = (InputMap) object;
			inputMap.put(keyStroke, action);
		}
	}
}
