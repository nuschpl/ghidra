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
package ghidra.app.plugin.gui;

import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import docking.action.builder.ActionBuilder;
import docking.options.editor.StringWithChoicesEditor;
import docking.theme.GTheme;
import docking.theme.GThemeDialog;
import docking.theme.Gui;
import docking.tool.ToolConstants;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.docking.util.LookAndFeelUtils;
import ghidra.framework.main.FrontEndOnly;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.SUPPORT,
	shortDescription = "Manages themes for the Ghdira GUI",
	description = "Adds actions and options to manage Themes within Ghidra. " +
			"This plugin is available only in the Ghidra Project Window."
)
//@formatter:on
public class ThemeManagerPlugin extends Plugin implements FrontEndOnly, OptionsChangeListener {

	public final static String THEME_OPTIONS_NAME = "Theme";
	private final static String OPTIONS_TITLE = ToolConstants.TOOL_OPTIONS;

	private boolean issuedRestartNotification;
//	private static boolean issuedPreferredDarkThemeLafNotification;

	public ThemeManagerPlugin(PluginTool tool) {
		super(tool);

		SystemUtilities.assertTrue(tool instanceof FrontEndTool,
			"Plugin added to the wrong type of tool");
		initThemeOptions();
	}

	@Override
	protected void init() {
		new ActionBuilder("Dump UI Properties", getName())
				.menuPath("Edit", "Dump UI Properies")
				.onAction(e -> LookAndFeelUtils.dumpUIProperties())
				.buildAndInstall(tool);

		new ActionBuilder("Show Properties", getName())
				.menuPath("Edit", "Theme Properties")
				.onAction(e -> showThemeProperties())
				.buildAndInstall(tool);

	}

	private void showThemeProperties() {
		GThemeDialog dialog = new GThemeDialog();
		tool.showDialog(dialog);
	}

	private void initThemeOptions() {

		ToolOptions opt = tool.getOptions(OPTIONS_TITLE);

		GTheme activeTheme = Gui.getActiveTheme();
		List<String> themeNames = getAllThemeNames();

		opt.registerOption(THEME_OPTIONS_NAME, OptionType.STRING_TYPE, activeTheme.getName(),
			new HelpLocation(ToolConstants.TOOL_HELP_TOPIC, "Look_And_Feel"),
			"Set the look and feel for Ghidra.  After you change the " +
				"look and feel, you will have to restart Ghidra to see the effect.",
			new StringWithChoicesEditor(themeNames));

		opt.addOptionsChangeListener(this);
	}

	private List<String> getAllThemeNames() {
		Set<GTheme> allThemes = Gui.getAllThemes();
		List<String> themeNames =
			allThemes.stream().map(t -> t.getName()).collect(Collectors.toList());
		Collections.sort(themeNames);
		return themeNames;
	}

	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) {

		if (optionName.equals(THEME_OPTIONS_NAME)) {
			String newThemeName = (String) newValue;
			if (!newThemeName.equals(Gui.getActiveTheme().getName())) {
				issueRestartNeededMessage();
			}

			saveLookAndFeel((String) newValue);
		}

	}

	private void saveLookAndFeel(String themeName) {
		Set<GTheme> allThemes = Gui.getAllThemes();
		for (GTheme theme : allThemes) {
			if (theme.getName().equals(themeName)) {
				Gui.saveThemeToPreferneces(theme);
			}
		}
	}

	private void issueRestartNeededMessage() {
		if (issuedRestartNotification) {
			return;
		}

		issuedRestartNotification = true;
		Msg.showInfo(getClass(), null, "Look And Feel Updated",
			"The new Look and Feel will take effect \nafter you exit and restart Ghidra.");
	}

	@Override
	public void dispose() {
		ToolOptions opt = tool.getOptions(OPTIONS_TITLE);
		opt.removeOptionsChangeListener(this);
		super.dispose();
	}
}
