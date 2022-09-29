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
package generic.theme;

import java.awt.*;
import java.io.File;
import java.util.*;
import java.util.List;

import javax.swing.*;
import javax.swing.plaf.ComponentUI;

import com.formdev.flatlaf.*;

import generic.theme.builtin.*;
import generic.theme.laf.LookAndFeelManager;
import ghidra.framework.OperatingSystem;
import ghidra.framework.Platform;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;
import resources.ResourceManager;
import utilities.util.reflection.ReflectionUtilities;

/**
 * Provides a static set of methods for globally managing application themes and their values.
 * <P>
 * The basic idea is that all the colors, fonts, and icons used in an application should be
 * accessed indirectly via an "id" string. Then the actual color, font, or icon can be changed 
 * without changing the source code. The default mapping of the id strings to a value is defined
 * in <name>.theme.properties files which are dynamically discovered by searching the module's
 * data directory. Also, these files can optionally define a dark default value for an id which
 * would replace the standard default value in the event that the current theme specifies that it
 * is a dark theme. Themes are used to specify the application's {@link LookAndFeel}, whether or
 * not it is dark, and any customized values for colors, fonts, or icons. There are several 
 * "built-in" themes, one for each supported {@link LookAndFeel}, but additional themes can
 * be defined and stored in the users application home directory as a <name>.theme file. 
 * 
 */
public class Gui {
	public static final String BACKGROUND_KEY = "color.bg.text";

	private static GTheme activeTheme = getDefaultTheme();
	private static Set<GTheme> allThemes = null;

	private static GThemeValueMap applicationDefaults = new GThemeValueMap();
	private static GThemeValueMap applicationDarkDefaults = new GThemeValueMap();
	private static GThemeValueMap javaDefaults = new GThemeValueMap();
	private static GThemeValueMap currentValues = new GThemeValueMap();
	private static GThemeValueMap systemValues = new GThemeValueMap();

	private static ThemeFileLoader themeFileLoader = new ThemeFileLoader();
	private static ThemePreferenceManager themePreferenceManager = new ThemePreferenceManager();

	private static Map<String, GColorUIResource> gColorMap = new HashMap<>();
	private static boolean isInitialized;
	private static Map<String, GIconUIResource> gIconMap = new HashMap<>();

	// these notifications are only when the user is manipulating theme values, so rare and at
	// user speed, so using copy on read
	private static WeakSet<ThemeListener> themeListeners =
		WeakDataStructureFactory.createCopyOnReadWeakSet();

	// stores the original value for ids whose value has changed from the current theme
	private static GThemeValueMap changedValuesMap = new GThemeValueMap();
	private static LookAndFeelManager lookAndFeelManager;
	static Font DEFAULT_FONT = new Font("Dialog", Font.PLAIN, 12);

	private Gui() {
		// static utils class, can't construct
	}

	/**
	 * Initialized the Theme and its values for the application.
	 */
	public static void initialize() {
		isInitialized = true;
		installFlatLookAndFeels();
		loadThemeDefaults();
		setTheme(themePreferenceManager.getTheme());
//		LookAndFeelUtils.installGlobalOverrides();
	}

	/**
	 * Reloads the defaults from all the discoverable theme.property files.
	 */
	public static void reloadApplicationDefaults() {
		loadThemeDefaults();
		buildCurrentValues();
		lookAndFeelManager.resetAll(javaDefaults);
		notifyThemeChanged(new AllValuesChangedThemeEvent(false));
	}

	/**
	 * Restores all the current application back to the values as specified by the active theme.
	 * In other words, reverts any changes to the active theme that haven't been saved.
	 */
	public static void restoreThemeValues() {
		buildCurrentValues();
		lookAndFeelManager.resetAll(javaDefaults);
		notifyThemeChanged(new AllValuesChangedThemeEvent(false));
	}

	/**
	 * Restores the current color value for the given color id to the value established by the
	 * current theme.
	 * @param id the color id to restore back to the original theme value
	 */
	public static void restoreColor(String id) {
		if (changedValuesMap.containsColor(id)) {
			Gui.setColor(changedValuesMap.getColor(id));
		}
	}

	/**
	 * Restores the current font value for the given font id to the value established by the
	 * current theme.
	 * @param id the font id to restore back to the original theme value
	 */
	public static void restoreFont(String id) {
		if (changedValuesMap.containsFont(id)) {
			Gui.setFont(changedValuesMap.getFont(id));
		}
	}

	/**
	 * Restores the current icon value for the given icon id to the value established by the
	 * current theme.
	 * @param id the icon id to restore back to the original theme value
	 */
	public static void restoreIcon(String id) {
		if (changedValuesMap.containsIcon(id)) {
			Gui.setIcon(changedValuesMap.getIcon(id));
		}
	}

	/**
	 * Returns true if the color associated with the given id has been changed from the current
	 * theme value for that id.
	 * @param id the color id to check if it has been changed
	 * @return true if the color associated with the given id has been changed from the current
	 * theme value for that id.
	 */
	public static boolean isChangedColor(String id) {
		return changedValuesMap.containsColor(id);
	}

	/**
	 * Returns true if the font associated with the given id has been changed from the current
	 * theme value for that id.
	 * @param id the font id to check if it has been changed
	 * @return true if the font associated with the given id has been changed from the current
	 * theme value for that id.
	 */
	public static boolean isChangedFont(String id) {
		return changedValuesMap.containsFont(id);
	}

	/**
	 * Returns true if the Icon associated with the given id has been changed from the current
	 * theme value for that id.
	 * @param id the Icon id to check if it has been changed
	 * @return true if the Icon associated with the given id has been changed from the current
	 * theme value for that id.
	 */
	public static boolean isChangedIcon(String id) {
		return changedValuesMap.containsIcon(id);
	}

	/**
	 * Sets the application's active theme to the given theme.
	 * @param theme the theme to make active
	 */
	public static void setTheme(GTheme theme) {
		if (theme.hasSupportedLookAndFeel()) {
			activeTheme = theme;
			LafType lookAndFeel = theme.getLookAndFeelType();
			lookAndFeelManager = lookAndFeel.getLookAndFeelManager();
			try {
				lookAndFeelManager.installLookAndFeel();
				themePreferenceManager.saveThemeToPreferences(theme);
				notifyThemeChanged(new AllValuesChangedThemeEvent(true));
			}
			catch (Exception e) {
				Msg.error(Gui.class,
					"Error setting LookAndFeel: " + lookAndFeel.getName(), e);
			}
		}
	}

	/**
	 * Adds the given theme to set of all themes.
	 * @param newTheme the theme to add
	 */
	public static void addTheme(GTheme newTheme) {
		loadThemes();
		allThemes.remove(newTheme);
		allThemes.add(newTheme);
	}

	/**
	 * Removes the theme from the set of all themes. Also, if the theme has an associated
	 * file, the file will be deleted.
	 * @param theme the theme to delete
	 */
	public static void deleteTheme(GTheme theme) {
		File file = theme.getFile();
		if (file != null) {
			file.delete();
		}
		if (allThemes != null) {
			allThemes.remove(theme);
		}
	}

	/**
	 * Returns a set of all known themes.
	 * @return a set of all known themes.
	 */
	public static Set<GTheme> getAllThemes() {
		loadThemes();
		return new HashSet<>(allThemes);
	}

	/**
	 * Returns a set of all known themes that are supported on the current platform.
	 * @return a set of all known themes that are supported on the current platform.
	 */
	public static Set<GTheme> getSupportedThemes() {
		loadThemes();
		Set<GTheme> supported = new HashSet<>();
		for (GTheme theme : allThemes) {
			if (theme.hasSupportedLookAndFeel()) {
				supported.add(theme);
			}
		}
		return supported;
	}

	/**
	 * Returns the active theme.
	 * @return the active theme.
	 */
	public static GTheme getActiveTheme() {
		return activeTheme;
	}

	/**
	 * Returns the {@link LafType} for the currently active {@link LookAndFeel}
	 * @return the {@link LafType} for the currently active {@link LookAndFeel}
	 */
	public static LafType getLookAndFeelType() {
		return activeTheme.getLookAndFeelType();
	}

	/**
	 * Returns the known theme that has the given name.
	 * @param themeName the name of the theme to retrieve
	 * @return the known theme that has the given name
	 */
	public static GTheme getTheme(String themeName) {
		Optional<GTheme> first =
			getAllThemes().stream().filter(t -> t.getName().equals(themeName)).findFirst();
		return first.orElse(null);
	}

	/**
	 * Returns a {@link GThemeValueMap} of all current theme values.
	 * @return a {@link GThemeValueMap} of all current theme values.
	 */
	public static GThemeValueMap getAllValues() {
		return new GThemeValueMap(currentValues);
	}

	/**
	 * Returns the theme values as defined by the current theme, ignoring any unsaved changes that
	 * are currently applied to the application.
	 * @return the theme values as defined by the current theme, ignoring any unsaved changes that
	 * are currently applied to the application.
	 */
	public static GThemeValueMap getThemeValues() {
		GThemeValueMap map = new GThemeValueMap();
		map.load(javaDefaults);
		map.load(systemValues);
		map.load(applicationDefaults);
		if (activeTheme.useDarkDefaults()) {
			map.load(applicationDarkDefaults);
		}
		map.load(activeTheme);
		return map;
	}

	/**
	 * Returns a {@link GThemeValueMap} contains all values that differ from the default
	 * values (values defined by the {@link LookAndFeel} or in the theme.properties files.
	 * @return a {@link GThemeValueMap} contains all values that differ from the defaults.
	 */
	public static GThemeValueMap getNonDefaultValues() {
		return currentValues.getChangedValues(getDefaults());
	}

	/**
	 * Returns the current {@link Font} associated with the given id. A default font will be
	 * returned if the font can't be resolved and an error message will be printed to the console.
	 * @param id the id for the desired font
	 * @return the current {@link Font} associated with the given id.
	 */
	public static Font getFont(String id) {
		return getFont(id, true);
	}

	/**
	 * Returns the current {@link Font} associated with the given id.
	 * @param id the id for the desired font
	 * @param validate if true, will print an error message to the console if the id can't be
	 * resolved
	 * @return the current {@link Font} associated with the given id.
	 */
	public static Font getFont(String id, boolean validate) {
		FontValue font = currentValues.getFont(id);

		if (font == null) {
			if (validate && isInitialized) {
				Throwable t = getFilteredTrace();
				Msg.error(Gui.class,
					"No color value registered for: '" + id + "'", t);
			}
			return DEFAULT_FONT;
		}
		return font.get(currentValues);
	}

	/**
	 * Returns the {@link Color} registered for the given id. Will output an error message if
	 * the id can't be resolved.
	 * @param id the id to get the direct color for
	 * @return the {@link Color} registered for the given id.
	 */
	public static Color getColor(String id) {
		return getColor(id, true);
	}

	/**
	 * Updates the current font for the given id.
	 * @param id the font id to update to the new color
	 * @param font the new font for the id
	 */
	public static void setFont(String id, Font font) {
		setFont(new FontValue(id, font));
	}

	/**
	 * Updates the current value for the font id in the newValue
	 * @param newValue the new {@link FontValue} to install in the current values.
	 */
	public static void setFont(FontValue newValue) {
		FontValue currentValue = currentValues.getFont(newValue.getId());
		if (newValue.equals(currentValue)) {
			return;
		}
		updateChangedValuesMap(currentValue, newValue);

		currentValues.addFont(newValue);
		notifyThemeChanged(new FontChangedThemeEvent(currentValues, newValue));

		// update all java LookAndFeel fonts affected by this changed
		String id = newValue.getId();
		Set<String> changedFontIds = findChangedJavaFontIds(id);
		lookAndFeelManager.fontsChanged(changedFontIds);
	}

	/**
	 * Updates the current color for the given id.
	 * @param id the color id to update to the new color
	 * @param color the new color for the id
	 */
	public static void setColor(String id, Color color) {
		setColor(new ColorValue(id, color));
	}

	/**
	 * Updates the current value for the color id in the newValue
	 * @param newValue the new {@link ColorValue} to install in the current values.
	 */
	public static void setColor(ColorValue newValue) {
		ColorValue currentValue = currentValues.getColor(newValue.getId());
		if (newValue.equals(currentValue)) {
			return;
		}
		updateChangedValuesMap(currentValue, newValue);
		currentValues.addColor(newValue);
		notifyThemeChanged(new ColorChangedThemeEvent(currentValues, newValue));

		// now update the ui
		lookAndFeelManager.colorsChanged();
	}

	/**
	 * Updates the current {@link Icon} for the given id.
	 * @param id the icon id to update to the new icon
	 * @param icon the new {@link Icon} for the id
	 */
	public static void setIcon(String id, Icon icon) {
		setIcon(new IconValue(id, icon));
	}

	/**
	 * Updates the current value for the {@link Icon} id in the newValue
	 * @param newValue the new {@link IconValue} to install in the current values.
	 */
	public static void setIcon(IconValue newValue) {
		IconValue currentValue = currentValues.getIcon(newValue.getId());
		if (newValue.equals(currentValue)) {
			return;
		}
		updateChangedValuesMap(currentValue, newValue);

		currentValues.addIcon(newValue);
		notifyThemeChanged(new IconChangedThemeEvent(currentValues, newValue));

		// now update the ui
		// update all java LookAndFeel icons affected by this changed
		String id = newValue.getId();
		Set<String> changedIconIds = findChangedJavaIconIds(id);
		Icon newIcon = newValue.get(currentValues);
		lookAndFeelManager.iconsChanged(changedIconIds, newIcon);
	}

	/**
	 * gets a UIResource version of the GColor for the given id. Using this method ensures that
	 * the same instance is used for a given id. This combats some poor code in some of the 
	 * {@link LookAndFeel}s where the use == in some places to test for equals.
	 * @param id the id to get a GColorUIResource for
	 * @return a GColorUIResource for the given id
	 */
	public static GColorUIResource getGColorUiResource(String id) {
		GColorUIResource gColor = gColorMap.get(id);
		if (gColor == null) {
			gColor = new GColorUIResource(id);
			gColorMap.put(id, gColor);
		}
		return gColor;
	}

	/**
	 * gets a UIResource version of the GIcon for the given id. Using this method ensures that
	 * the same instance is used for a given id. This combats some poor code in some of the 
	 * {@link LookAndFeel}s where the use == in some places to test for equals.
	 * @param id the id to get a {@link GIconUIResource} for
	 * @return a GIconUIResource for the given id
	 */
	public static GIconUIResource getGIconUiResource(String id) {

		GIconUIResource gIcon = gIconMap.get(id);
		if (gIcon == null) {
			gIcon = new GIconUIResource(id);
			gIconMap.put(id, gIcon);
		}
		return gIcon;
	}

	public static void setSystemDefaults(GThemeValueMap map) {
		systemValues = map;
	}

	/**
	 * Sets the map of JavaDefaults defined by the current {@link LookAndFeel}.
	 * @param map the default theme values defined by the {@link LookAndFeel}
	 */
	public static void setJavaDefaults(GThemeValueMap map) {
		javaDefaults = map;
		buildCurrentValues();
		GColor.refreshAll();
		GIcon.refreshAll();
	}

	/**
	 * Returns the {@link GThemeValueMap} containing all the default theme values defined by the
	 * current {@link LookAndFeel}.
	 * @return  the {@link GThemeValueMap} containing all the default theme values defined by the
	 * current {@link LookAndFeel}
	 */
	public static GThemeValueMap getJavaDefaults() {
		GThemeValueMap map = new GThemeValueMap();
		map.load(javaDefaults);
		return map;
	}

	/**
	 * Returns the {@link GThemeValueMap} containing all the dark default values defined
	 * in theme.properties files. Note that dark defaults includes light defaults that haven't
	 * been overridden by a dark default with the same id.
	 * @return the {@link GThemeValueMap} containing all the dark values defined in 
	 * theme.properties files
	 */
	public static GThemeValueMap getApplicationDarkDefaults() {
		GThemeValueMap map = new GThemeValueMap(applicationDefaults);
		map.load(applicationDarkDefaults);
		return map;
	}

	/**
	 * Returns the {@link GThemeValueMap} containing all the standard default values defined
	 * in theme.properties files. 
	 * @return the {@link GThemeValueMap} containing all the standard values defined in 
	 * theme.properties files
	 */
	public static GThemeValueMap getApplicationLightDefaults() {
		GThemeValueMap map = new GThemeValueMap(applicationDefaults);
		return map;
	}

	/**
	 * Returns a {@link GThemeValueMap} containing all default values for the current theme. It
	 * is a combination of application defined defaults and java {@link LookAndFeel} defaults.
	 * @return the current set of defaults.
	 */
	public static GThemeValueMap getDefaults() {
		GThemeValueMap currentDefaults = new GThemeValueMap(javaDefaults);
		currentDefaults.load(systemValues);
		currentDefaults.load(applicationDefaults);
		if (activeTheme.useDarkDefaults()) {
			currentDefaults.load(applicationDarkDefaults);
		}
		return currentDefaults;
	}

	/**
	 * Returns true if the given UI object is using the Aqua Look and Feel.
	 * @param UI the UI to examine.
	 * @return true if the UI is using Aqua
	 */
	public static boolean isUsingAquaUI(ComponentUI UI) {
		return activeTheme.getLookAndFeelType() == LafType.MAC;
	}

	/**
	 * Returns true if 'Nimbus' is the current Look and Feel
	 * @return true if 'Nimbus' is the current Look and Feel
	 */
	public static boolean isUsingNimbusUI() {
		return activeTheme.getLookAndFeelType() == LafType.NIMBUS;
	}

	/**
	 * Adds a {@link ThemeListener} to be notified of theme changes.
	 * @param listener the listener to be notified
	 */
	public static void addThemeListener(ThemeListener listener) {
		themeListeners.add(listener);
	}

	/**
	 * Removes the given {@link ThemeListener} from the list of listeners to be notified of
	 * theme changes.
	 * @param listener the listener to be removed
	 */
	public static void removeThemeListener(ThemeListener listener) {
		themeListeners.add(listener);
	}

	/**
	 * Returns the default theme for the current platform.
	 * @return the default theme for the current platform.
	 */
	public static GTheme getDefaultTheme() {
		OperatingSystem OS = Platform.CURRENT_PLATFORM.getOperatingSystem();
		switch (OS) {
			case MAC_OS_X:
				return new MacTheme();
			case WINDOWS:
				return new WindowsTheme();
			case LINUX:
			case UNSUPPORTED:
			default:
				return new NimbusTheme();
		}
	}

	/**
	 * Returns true if there are any unsaved changes to the current theme.
	 * @return true if there are any unsaved changes to the current theme.
	 */
	public static boolean hasThemeChanges() {
		return !changedValuesMap.isEmpty();
	}

	/**
	 * Returns the color for the id. If there is no color registered for this id, then Color.CYAN
	 * is returned as the default color. 
	 * @param id the id to get the direct color for
	 * @param validate if true, will output an error if the id can't be resolved at this time
	 * @return the actual direct color for the id, not a GColor
	 */
	public static Color getColor(String id, boolean validate) {
		ColorValue color = currentValues.getColor(id);

		if (color == null) {
			if (validate && isInitialized) {
				Throwable t = getFilteredTrace();
				Msg.error(Gui.class,
					"No color value registered for: '" + id + "'", t);
			}
			return Color.CYAN;
		}
		return color.get(currentValues);
	}

	/**
	 * Returns the Icon registered for the given id. If no icon is registered for the id,
	 * the default icon will be returned and an error message will be dumped to the console
	 * @param id the id to get the registered icon for
	 * @return the actual icon registered for the given id
	 */
	public static Icon getIcon(String id) {
		return getIcon(id, true);
	}

	/**
	 * Returns the {@link Icon} registered for the given id. If no icon is registered, returns
	 * the default icon (bomb).
	 * @param id the id to get the register icon for
	 * @param validate if true, will output an error if the id can't be resolved at this time
	 * @return the Icon registered for the given id
	 */
	public static Icon getIcon(String id, boolean validate) {
		IconValue icon = currentValues.getIcon(id);
		if (icon == null) {
			if (validate && isInitialized) {
				Throwable t = getFilteredTrace();
				Msg.error(Gui.class,
					"No icon value registered for: '" + id + "'", t);
			}
			return ResourceManager.getDefaultIcon();
		}
		return icon.get(currentValues);
	}

	/**
	 * Returns a darker version of the given color or brighter if the current theme is dark.
	 * @param color the color to get a darker version of
	 * @return a darker version of the given color or brighter if the current theme is dark
	 */
	public static Color darker(Color color) {
		if (activeTheme.useDarkDefaults()) {
			return color.brighter();
		}
		return color.darker();
	}

	/**
	 * Returns a brighter version of the given color or darker if the current theme is dark.
	 * @param color the color to get a brighter version of
	 * @return a brighter version of the given color or darker if the current theme is dark
	 */
	public static Color brighter(Color color) {
		if (activeTheme.useDarkDefaults()) {
			return color.darker();
		}
		return color.brighter();
	}

	/**
	 * Binds the component to the font identified by the given font id. Whenever the font for
	 * the font id changes, the component will updated with the new font.
	 * @param component the component to set/update the font
	 * @param fontId the id of the font to register with the given component
	 */
	public static void registerFont(Component component, String fontId) {
		lookAndFeelManager.registerFont(component, fontId);
	}

	private static void installFlatLookAndFeels() {
		UIManager.installLookAndFeel(LafType.FLAT_LIGHT.getName(), FlatLightLaf.class.getName());
		UIManager.installLookAndFeel(LafType.FLAT_DARK.getName(), FlatDarkLaf.class.getName());
		UIManager.installLookAndFeel(LafType.FLAT_DARCULA.getName(),
			FlatDarculaLaf.class.getName());
	}

	private static void loadThemeDefaults() {
		themeFileLoader.loadThemeDefaultFiles();
		applicationDefaults = themeFileLoader.getDefaults();
		applicationDarkDefaults = themeFileLoader.getDarkDefaults();
	}

	private static void notifyThemeChanged(ThemeEvent event) {
		for (ThemeListener listener : themeListeners) {
			listener.themeChanged(event);
		}
	}

	private static Throwable getFilteredTrace() {
		Throwable t = ReflectionUtilities.createThrowableWithStackOlderThan();
		StackTraceElement[] trace = t.getStackTrace();
		StackTraceElement[] filtered =
			ReflectionUtilities.filterStackTrace(trace, "java.", "theme.Gui", "theme.GColor");
		t.setStackTrace(filtered);
		return t;
	}

	private static void buildCurrentValues() {
		GThemeValueMap map = new GThemeValueMap();

		map.load(javaDefaults);
		map.load(systemValues);
		map.load(applicationDefaults);
		if (activeTheme.useDarkDefaults()) {
			map.load(applicationDarkDefaults);
		}
		map.load(activeTheme);
		currentValues = map;
		changedValuesMap.clear();
	}

	private static void loadThemes() {
		if (allThemes == null) {
			Set<GTheme> set = new HashSet<>();
			set.addAll(findDiscoverableThemes());
			set.addAll(themeFileLoader.loadThemeFiles());
			allThemes = set;
		}
	}

	private static Collection<DiscoverableGTheme> findDiscoverableThemes() {
		return ClassSearcher.getInstances(DiscoverableGTheme.class);
	}

	private static void updateChangedValuesMap(ColorValue currentValue, ColorValue newValue) {
		String id = newValue.getId();
		ColorValue originalValue = changedValuesMap.getColor(id);

		// if new value is original value, it is no longer changed, remove it from changed map
		if (newValue.equals(originalValue)) {
			changedValuesMap.removeColor(id);
		}
		else if (originalValue == null) {
			// first time changed, so current value is original value
			changedValuesMap.addColor(currentValue);
		}
	}

	private static void updateChangedValuesMap(FontValue currentValue, FontValue newValue) {
		String id = newValue.getId();
		FontValue originalValue = changedValuesMap.getFont(id);

		// if new value is original value, it is no longer changed, remove it from changed map
		if (newValue.equals(originalValue)) {
			changedValuesMap.removeFont(id);
		}
		else if (originalValue == null) {
			// first time changed, so current value is original value
			changedValuesMap.addFont(currentValue);
		}
	}

	private static void updateChangedValuesMap(IconValue currentValue, IconValue newValue) {
		String id = newValue.getId();
		IconValue originalValue = changedValuesMap.getIcon(id);

		// if new value is original value, it is no longer changed, remove it from changed map
		if (newValue.equals(originalValue)) {
			changedValuesMap.removeIcon(id);
		}
		else if (originalValue == null) {
			// first time changed, so current value is original value
			changedValuesMap.addIcon(currentValue);
		}
	}

	private static Set<String> findChangedJavaFontIds(String id) {
		Set<String> affectedIds = new HashSet<>();
		List<FontValue> fonts = javaDefaults.getFonts();
		for (FontValue fontValue : fonts) {
			String fontId = fontValue.getId();
			FontValue currentFontValue = currentValues.getFont(fontId);
			if (fontId.equals(id) || currentFontValue.inheritsFrom(id, currentValues)) {
				affectedIds.add(fontId);
			}
		}
		return affectedIds;
	}

	private static Set<String> findChangedJavaIconIds(String id) {
		Set<String> affectedIds = new HashSet<>();
		List<IconValue> icons = javaDefaults.getIcons();
		for (IconValue iconValue : icons) {
			String iconId = iconValue.getId();
			if (iconId.equals(id) || iconValue.inheritsFrom(id, currentValues)) {
				affectedIds.add(iconId);
			}
		}
		return affectedIds;
	}

	// for testing
	public static void setPropertiesLoader(ThemeFileLoader loader) {
		allThemes = null;
		themeFileLoader = loader;
	}

	public static void setThemePreferenceManager(ThemePreferenceManager manager) {
		themePreferenceManager = manager;
	}

}
