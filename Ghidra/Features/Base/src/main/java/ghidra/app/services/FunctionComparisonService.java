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
package ghidra.app.services;

import java.util.Set;

import docking.ComponentProviderActivationListener;
import ghidra.app.plugin.core.functioncompare.FunctionComparisonPlugin;
import ghidra.app.plugin.core.functioncompare.FunctionComparisonProvider;
import ghidra.framework.plugintool.ServiceInfo;
import ghidra.program.model.listing.Function;

/**
 * Allows users to create comparisons between functions which will be displayed
 * side-by-side in a {@link FunctionComparisonProvider}
 */
@ServiceInfo(defaultProvider = FunctionComparisonPlugin.class)
public interface FunctionComparisonService {

	/**
	 * Creates a comparison between a set of functions, where each function
	 * in the list can be compared against any other function in the list
	 * 
	 * @param functions the functions to compare
	 * @return the new comparison provider
	 */
	public FunctionComparisonProvider compareFunctions(Set<Function> functions);

	/**
	 * Creates a comparison between two functions
	 * 
	 * @param source a function in the comparison
	 * @param target a function in the comparison
	 * @return the comparison provider
	 */
	public FunctionComparisonProvider compareFunctions(Function source,
			Function target);

	/**
	 * Creates a comparison between a set of functions, adding them to the 
	 * given comparison provider
	 * 
	 * @param functions the functions to compare
	 * @param provider the provider to add the comparisons to
	 */
	public void compareFunctions(Set<Function> functions,
			FunctionComparisonProvider provider);

	/**
	 * Creates a comparison between two functions and adds it to a given
	 * comparison provider
	 * 
	 * @param source a function in the comparison
	 * @param target a function in the comparison
	 * @param provider the provider to add the comparison to
	 */
	public void compareFunctions(Function source, Function target,
			FunctionComparisonProvider provider);

	/**
	 * Removes a given function from all comparisons across all comparison 
	 * providers
	 * 
	 * @param function the function to remove
	 */
	public void removeFunction(Function function);

	/**
	 * Removes a given function from all comparisons in the given comparison
	 * provider
	 * 
	 * @param function the function to remove
	 * @param provider the comparison provider to remove functions from
	 */
	public void removeFunction(Function function, FunctionComparisonProvider provider);

	/**
	 * Adds the given listener to the list of subscribers who wish to be 
	 * notified of provider activation events (eg: provider open/close)
	 * 
	 * @param listener the listener to be added
	 */
	public void addFunctionComparisonProviderListener(ComponentProviderActivationListener listener);
}
