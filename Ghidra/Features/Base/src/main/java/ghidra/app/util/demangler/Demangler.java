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
package ghidra.app.util.demangler;

import ghidra.program.model.listing.Program;
import ghidra.util.classfinder.ExtensionPoint;

/**
 * NOTE:  ALL DEMANGLER CLASSES MUST END IN "Demangler".  If not,
 * the ClassSearcher will not find them.
 */
public interface Demangler extends ExtensionPoint {

	public boolean canDemangle(Program program);

	// TODO deprecate
	@Deprecated
	public DemangledObject demangle(String mangled, boolean demangleOnlyKnownPatterns)
			throws DemangledException;

	// TODO docme
	public DemangledObject demangle(String mangled, DemanglerOptions options)
			throws DemangledException;

	public default DemanglerOptions createDefaultOptions() {
		return new DemanglerOptions();
	}
}
